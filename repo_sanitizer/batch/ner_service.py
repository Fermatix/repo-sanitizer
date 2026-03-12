"""NER HTTP service for batch mode.

Loads the NER model once on GPU and serves inference requests to worker
processes over a local HTTP API. This prevents N worker processes from each
loading their own copy of the model into VRAM.

API:
    GET  /health  → {"status": "ready" | "loading"}
    POST /ner     → body: {"texts": ["...", ...]}
                  → response: {"results": [[{entity}, ...], ...]}

Entity format matches HuggingFace pipeline with aggregation_strategy="simple":
    {"entity_group": "PER", "score": 0.95, "word": "John Doe", "start": 0, "end": 8}

Dynamic batching (inference-time accumulation): the batcher waits for the first
request, yields one event-loop tick so all concurrent HTTP handlers can enqueue
their chunks, then drains the queue and dispatches a single GPU call. The batch
size self-adjusts to load — no arbitrary timeout needed.

Idle shutdown: if no /ner requests are received for ``idle_timeout`` seconds,
the service sends SIGTERM to itself and exits cleanly. Pass ``idle_timeout=0``
to disable.
"""
import asyncio
import logging
import multiprocessing
import os
import signal
import time
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# FastAPI application (runs inside the service process)
# ---------------------------------------------------------------------------

def _make_app(
    model_name: str,
    device: str,
    batch_size: int,
    backend: str,
    min_score: float,
    entity_types: list[str],
    idle_timeout: float = 0.0,
) -> Any:
    from fastapi import FastAPI, Request
    from fastapi.responses import JSONResponse

    app = FastAPI(title="NER Service")
    _pipeline: Any = None
    _gliner: Any = None
    _queue: asyncio.Queue = asyncio.Queue()
    _last_request_time: float = time.monotonic()

    def _run_hf(texts: list[str]) -> list[list[dict]]:
        raw = _pipeline(texts, batch_size=batch_size)
        # HF quirk: single-text call returns a flat list instead of list-of-lists
        if texts and isinstance(raw[0], dict):
            raw = [raw]
        return raw

    def _run_gliner(texts: list[str]) -> list[list[dict]]:
        from repo_sanitizer.detectors.ner import GLINER_LABEL_MAP, _GLINER_LABEL_REVERSE
        labels = [GLINER_LABEL_MAP.get(et, et.lower()) for et in entity_types]
        results = []
        for text in texts:
            entities = _gliner.predict_entities(text, labels, threshold=min_score)
            chunk_results = []
            for ent in entities:
                code = _GLINER_LABEL_REVERSE.get(ent["label"], ent["label"].upper())
                chunk_results.append({
                    "entity_group": code,
                    "score": ent["score"],
                    "word": ent["text"],
                    "start": ent["start"],
                    "end": ent["end"],
                })
            results.append(chunk_results)
        return results

    async def _batching_loop() -> None:
        """Inference-time accumulation: collect all pending requests, then one GPU call."""
        loop = asyncio.get_running_loop()
        _infer = _run_gliner if backend == "gliner" else _run_hf
        while True:
            # Block until at least one request arrives
            texts0, fut0 = await _queue.get()
            # One event-loop tick lets pending HTTP handlers complete their put()
            await asyncio.sleep(0)
            batch_items: list[tuple[list[str], asyncio.Future]] = [(texts0, fut0)]
            # Drain everything else that arrived while we were waiting
            while not _queue.empty():
                batch_items.append(_queue.get_nowait())

            all_texts = [t for texts, _ in batch_items for t in texts]
            try:
                raw = await loop.run_in_executor(None, lambda: _infer(all_texts))
            except Exception as exc:
                for _, fut in batch_items:
                    if not fut.done():
                        fut.set_exception(exc)
                continue

            offset = 0
            for texts, fut in batch_items:
                n = len(texts)
                if not fut.done():
                    fut.set_result(raw[offset : offset + n])
                offset += n

    async def _idle_watchdog() -> None:
        """Shut down the service if no /ner requests for idle_timeout seconds."""
        nonlocal _last_request_time
        while True:
            await asyncio.sleep(10)
            if time.monotonic() - _last_request_time > idle_timeout:
                logger.info("NER service idle for %.0fs, shutting down.", idle_timeout)
                os.kill(os.getpid(), signal.SIGTERM)
                return

    @app.on_event("startup")
    async def _startup() -> None:
        nonlocal _pipeline, _gliner
        from repo_sanitizer.detectors.ner import NERDetector
        resolved = NERDetector._resolve_device(device)
        logger.info("Loading NER model '%s' on device '%s' (backend=%s)", model_name, resolved, backend)
        if backend == "gliner":
            try:
                import torch
                from gliner import GLiNER
                torch_device = torch.device(resolved if resolved != "auto" else "cpu")
                _gliner = GLiNER.from_pretrained(model_name, map_location=torch_device)
                _gliner = _gliner.to(torch_device)
                _gliner.device = torch_device
            except Exception as e:
                raise RuntimeError(f"Failed to load GLiNER model '{model_name}': {e}")
        else:
            from transformers import pipeline as hf_pipeline
            try:
                if resolved == "auto":
                    _pipeline = hf_pipeline(
                        "ner", model=model_name, aggregation_strategy="simple", device_map="auto"
                    )
                else:
                    _pipeline = hf_pipeline(
                        "ner", model=model_name, aggregation_strategy="simple", device=resolved
                    )
            except Exception as e:
                raise RuntimeError(f"Failed to load NER model '{model_name}': {e}")
        logger.info("NER model ready; starting dynamic batcher")
        asyncio.create_task(_batching_loop())
        if idle_timeout > 0:
            asyncio.create_task(_idle_watchdog())

    @app.get("/health")
    def health() -> JSONResponse:
        ready = (_gliner is not None) if backend == "gliner" else (_pipeline is not None)
        return JSONResponse({"status": "ready" if ready else "loading"})

    @app.post("/ner")
    async def ner(request: Request) -> JSONResponse:
        nonlocal _last_request_time
        _last_request_time = time.monotonic()
        body = await request.json()
        texts = body.get("texts", [])
        if not texts:
            return JSONResponse({"results": []})

        loop = asyncio.get_running_loop()
        fut: asyncio.Future = loop.create_future()
        await _queue.put((texts, fut))
        raw: list = await fut

        results = [
            [
                {
                    "entity_group": e.get("entity_group", ""),
                    "score": float(e.get("score", 0)),
                    "word": e.get("word", ""),
                    "start": int(e.get("start", 0)),
                    "end": int(e.get("end", 0)),
                }
                for e in entities
            ]
            for entities in raw
        ]
        return JSONResponse({"results": results})

    return app


def _run_server(
    model_name: str,
    device: str,
    port: int,
    batch_size: int,
    backend: str,
    min_score: float,
    entity_types: list[str],
    idle_timeout: float = 0.0,
) -> None:
    """Entry point for the service subprocess."""
    import uvicorn

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-5s [NER] %(message)s",
        datefmt="%H:%M:%S",
    )
    for name in ("transformers", "filelock", "huggingface_hub", "urllib3", "httpx"):
        logging.getLogger(name).setLevel(logging.ERROR)

    app = _make_app(model_name, device, batch_size, backend, min_score, entity_types, idle_timeout)
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="warning")


# ---------------------------------------------------------------------------
# Public API: launch / stop
# ---------------------------------------------------------------------------

def _is_port_in_use(port: int) -> bool:
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(("127.0.0.1", port)) == 0


def launch_ner_service(
    model_name: str,
    device: str,
    port: int,
    batch_size: int = 32,
    timeout: float = 180.0,
    backend: str = "hf",
    min_score: float = 0.7,
    entity_types: list[str] | None = None,
) -> multiprocessing.Process:
    """Start the NER service in a daemon subprocess and wait until it's ready.

    Returns the process handle so the caller can terminate it when done.
    Raises ``RuntimeError`` if the port is already in use or the process dies.
    Raises ``TimeoutError`` if the service does not become ready within *timeout* seconds.

    Args:
        batch_size: Maximum number of text chunks in a single GPU forward pass.
            The batcher naturally fills up to this size using inference-time
            accumulation — no fixed wait timeout needed.
        backend: ``"hf"`` for HuggingFace transformers, ``"gliner"`` for GLiNER.
        min_score: Minimum confidence threshold (GLiNER only).
        entity_types: Entity type codes to detect (GLiNER only, e.g. ``["PER", "ORG"]``).
    """
    if entity_types is None:
        entity_types = ["PER", "ORG"]

    if _is_port_in_use(port):
        raise RuntimeError(
            f"Port {port} is already in use. A previous NER service may still be running. "
            f"Kill it with: fuser -k {port}/tcp"
        )

    proc = multiprocessing.Process(
        target=_run_server,
        args=(model_name, device, port, batch_size, backend, min_score, entity_types),
        daemon=True,
        name="ner-service",
    )
    proc.start()
    logger.info(
        "NER service starting (model=%s, backend=%s, device=%s, port=%d, batch_size=%d, pid=%d)",
        model_name,
        backend,
        device,
        port,
        batch_size,
        proc.pid,
    )

    _wait_for_ready(port, timeout, proc)
    logger.info("NER service is ready on port %d", port)
    return proc


def _wait_for_ready(port: int, timeout: float, proc: multiprocessing.Process) -> None:
    import httpx

    deadline = time.monotonic() + timeout
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        if not proc.is_alive():
            raise RuntimeError(
                f"NER service process died (exit code: {proc.exitcode}). "
                f"Port {port} may already be in use by a previous run. "
                f"Kill it with: fuser -k {port}/tcp"
            )
        try:
            resp = httpx.get(f"http://127.0.0.1:{port}/health", timeout=3.0)
            if resp.json().get("status") == "ready":
                return
        except Exception as exc:
            last_exc = exc
        time.sleep(2)

    raise TimeoutError(
        f"NER service did not become ready within {timeout:.0f}s "
        f"(last error: {last_exc})"
    )
