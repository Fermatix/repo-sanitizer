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

Dynamic batching: requests from concurrent workers are collected within a short
time window (max_wait_ms) and dispatched as a single GPU batch, achieving true
GPU parallelism instead of sequential 1-sample inference.
"""
import asyncio
import logging
import multiprocessing
import time
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# FastAPI application (runs inside the service process)
# ---------------------------------------------------------------------------

def _make_app(model_name: str, device: str, batch_size: int, max_wait_ms: int) -> Any:
    from fastapi import FastAPI, Request
    from fastapi.responses import JSONResponse

    app = FastAPI(title="NER Service")
    _pipeline: Any = None
    _queue: asyncio.Queue = asyncio.Queue()

    def _normalize_results(raw: list, n_texts: int) -> list:
        """Ensure raw pipeline output is list-of-lists regardless of HF quirks."""
        if raw and isinstance(raw[0], dict):
            raw = [raw]
        return raw

    async def _batching_loop() -> None:
        """Collect concurrent requests and dispatch as a single GPU batch."""
        loop = asyncio.get_running_loop()
        while True:
            # Block until at least one request arrives
            texts0, fut0 = await _queue.get()
            batch_items: list[tuple[list[str], asyncio.Future]] = [(texts0, fut0)]

            # Collect additional requests within the time window
            deadline = loop.time() + max_wait_ms / 1000.0
            while len(batch_items) < batch_size:
                remaining = deadline - loop.time()
                if remaining <= 0:
                    break
                try:
                    item = await asyncio.wait_for(_queue.get(), timeout=remaining)
                    batch_items.append(item)
                except asyncio.TimeoutError:
                    break

            # Flatten all texts into one list for a single GPU call
            all_texts = [t for texts, _ in batch_items for t in texts]
            try:
                raw = await loop.run_in_executor(
                    None, lambda: _pipeline(all_texts, batch_size=batch_size)
                )
                # Defensive normalisation: single-text call may return a flat list
                if all_texts and isinstance(raw[0], dict):
                    raw = [raw]
            except Exception as exc:
                for _, fut in batch_items:
                    if not fut.done():
                        fut.set_exception(exc)
                continue

            # Distribute results back to each waiting future
            offset = 0
            for texts, fut in batch_items:
                n = len(texts)
                if not fut.done():
                    fut.set_result(raw[offset : offset + n])
                offset += n

    @app.on_event("startup")
    async def _startup() -> None:
        nonlocal _pipeline
        from transformers import pipeline as hf_pipeline
        from repo_sanitizer.detectors.ner import NERDetector

        resolved = NERDetector._resolve_device(device)
        logger.info("Loading NER model '%s' on device '%s'", model_name, resolved)
        if resolved == "auto":
            _pipeline = hf_pipeline(
                "ner",
                model=model_name,
                aggregation_strategy="simple",
                device_map="auto",
            )
        else:
            _pipeline = hf_pipeline(
                "ner",
                model=model_name,
                aggregation_strategy="simple",
                device=resolved,
            )
        logger.info("NER model ready; starting dynamic batcher (max_wait_ms=%d)", max_wait_ms)
        asyncio.create_task(_batching_loop())

    @app.get("/health")
    def health() -> JSONResponse:
        ready = (_gliner is not None) if backend == "gliner" else (_pipeline is not None)
        return JSONResponse({"status": "ready" if ready else "loading"})

    @app.post("/ner")
    async def ner(request: Request) -> JSONResponse:
        import asyncio
        from repo_sanitizer.detectors.ner import GLINER_LABEL_MAP, _GLINER_LABEL_REVERSE, LABEL_MAP
        body = await request.json()
        texts = body.get("texts", [])
        if not texts:
            return JSONResponse({"results": [[] for _ in texts]})

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

        results = await loop.run_in_executor(None, _run_pipeline)
        return JSONResponse({"results": results})

    return app


def _run_server(model_name: str, device: str, port: int, batch_size: int, max_wait_ms: int) -> None:
    """Entry point for the service subprocess."""
    import uvicorn

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-5s [NER] %(message)s",
        datefmt="%H:%M:%S",
    )
    for name in ("transformers", "filelock", "huggingface_hub", "urllib3", "httpx"):
        logging.getLogger(name).setLevel(logging.ERROR)

    app = _make_app(model_name, device, batch_size, max_wait_ms)
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
    max_wait_ms: int = 20,
    timeout: float = 180.0,
    backend: str = "transformers",
) -> multiprocessing.Process:
    """Start the NER service in a daemon subprocess and wait until it's ready.

    Returns the process handle so the caller can terminate it when done.
    Raises ``RuntimeError`` if the port is already in use or the process dies.
    Raises ``TimeoutError`` if the service does not become ready within *timeout* seconds.

    Args:
        batch_size: Maximum number of text chunks per GPU batch.
        max_wait_ms: How long (ms) to wait for additional requests before
            dispatching a batch. Higher values improve GPU utilisation at the
            cost of individual request latency. Default 20 ms is a good
            trade-off for 8–32 concurrent workers.
    """
    if _is_port_in_use(port):
        raise RuntimeError(
            f"Port {port} is already in use. A previous NER service may still be running. "
            f"Kill it with: fuser -k {port}/tcp"
        )

    proc = multiprocessing.Process(
        target=_run_server,
        args=(model_name, device, port, batch_size, max_wait_ms),
        daemon=True,
        name="ner-service",
    )
    proc.start()
    logger.info(
        "NER service starting (model=%s, device=%s, port=%d, batch_size=%d, max_wait_ms=%d, pid=%d)",
        model_name,
        device,
        port,
        batch_size,
        max_wait_ms,
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
