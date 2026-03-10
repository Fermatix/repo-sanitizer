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
"""
import logging
import multiprocessing
import time
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# FastAPI application (runs inside the service process)
# ---------------------------------------------------------------------------

def _make_app(model_name: str, device: str, batch_size: int, backend: str = "transformers") -> Any:
    from fastapi import FastAPI, Request
    from fastapi.responses import JSONResponse

    app = FastAPI(title="NER Service")
    _pipeline: Any = None
    _gliner: Any = None

    @app.on_event("startup")
    def _load_model() -> None:
        nonlocal _pipeline, _gliner
        from repo_sanitizer.detectors.ner import NERDetector, GLINER_LABEL_MAP, _GLINER_LABEL_REVERSE
        if backend == "gliner":
            from gliner import GLiNER
            logger.info("Loading GLiNER model '%s'", model_name)
            _gliner = GLiNER.from_pretrained(model_name)
            logger.info("GLiNER model ready")
        else:
            from transformers import pipeline as hf_pipeline
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
            logger.info("NER model ready")

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

        loop = asyncio.get_event_loop()

        if backend == "gliner":
            if _gliner is None:
                return JSONResponse({"results": [[] for _ in texts]})
            labels = list(GLINER_LABEL_MAP.values())

            def _run_gliner() -> list:
                results = []
                for text in texts:
                    entities = _gliner.predict_entities(text, labels)
                    converted = []
                    for ent in entities:
                        code = _GLINER_LABEL_REVERSE.get(ent["label"], ent["label"].upper())
                        converted.append({
                            "entity_group": code,
                            "score": float(ent["score"]),
                            "word": ent["text"],
                            "start": int(ent["start"]),
                            "end": int(ent["end"]),
                        })
                    results.append(converted)
                return results

            results = await loop.run_in_executor(None, _run_gliner)
            return JSONResponse({"results": results})

        if _pipeline is None:
            return JSONResponse({"results": [[] for _ in texts]})

        def _run_pipeline() -> list:
            # Pass the full list for true GPU batching; pipeline returns list-of-lists
            raw = _pipeline(texts, batch_size=batch_size)
            # Defensive normalisation: single-string path returns a flat list
            if texts and isinstance(raw[0], dict):
                raw = [raw]
            return [
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

        results = await loop.run_in_executor(None, _run_pipeline)
        return JSONResponse({"results": results})

    return app


def _run_server(model_name: str, device: str, port: int, batch_size: int, backend: str = "transformers") -> None:
    """Entry point for the service subprocess."""
    import uvicorn

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-5s [NER] %(message)s",
        datefmt="%H:%M:%S",
    )
    for name in ("transformers", "filelock", "huggingface_hub", "urllib3", "httpx"):
        logging.getLogger(name).setLevel(logging.ERROR)

    app = _make_app(model_name, device, batch_size, backend)
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
    backend: str = "transformers",
) -> multiprocessing.Process:
    """Start the NER service in a daemon subprocess and wait until it's ready.

    Returns the process handle so the caller can terminate it when done.
    Raises ``RuntimeError`` if the port is already in use or the process dies.
    Raises ``TimeoutError`` if the service does not become ready within *timeout* seconds.
    """
    if _is_port_in_use(port):
        raise RuntimeError(
            f"Port {port} is already in use. A previous NER service may still be running. "
            f"Kill it with: fuser -k {port}/tcp"
        )

    proc = multiprocessing.Process(
        target=_run_server,
        args=(model_name, device, port, batch_size, backend),
        daemon=True,
        name="ner-service",
    )
    proc.start()
    logger.info(
        "NER service starting (model=%s, device=%s, port=%d, pid=%d)",
        model_name,
        device,
        port,
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
