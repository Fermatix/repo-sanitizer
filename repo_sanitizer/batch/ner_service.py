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
from __future__ import annotations

import logging
import multiprocessing
import time
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# FastAPI application (runs inside the service process)
# ---------------------------------------------------------------------------

def _make_app(model_name: str, device: str, batch_size: int) -> Any:
    from fastapi import FastAPI, Request
    from fastapi.responses import JSONResponse

    app = FastAPI(title="NER Service")
    _pipeline: Any = None

    @app.on_event("startup")
    def _load_model() -> None:
        nonlocal _pipeline
        from transformers import pipeline as hf_pipeline
        logger.info("Loading NER model '%s' on device '%s'", model_name, device)
        if device == "auto":
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
                device=device,
            )
        logger.info("NER model ready")

    @app.get("/health")
    def health() -> JSONResponse:
        return JSONResponse({"status": "ready" if _pipeline is not None else "loading"})

    @app.post("/ner")
    async def ner(request: Request) -> JSONResponse:
        body = await request.json()
        texts = body.get("texts", [])
        results = []
        for text in texts:
            entities = _pipeline(text) if _pipeline is not None else []
            results.append(
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
            )
        return JSONResponse({"results": results})

    return app


def _run_server(model_name: str, device: str, port: int, batch_size: int) -> None:
    """Entry point for the service subprocess."""
    import uvicorn

    logging.basicConfig(level=logging.INFO, format="%(asctime)s [NER] %(message)s")
    app = _make_app(model_name, device, batch_size)
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="warning")


# ---------------------------------------------------------------------------
# Public API: launch / stop
# ---------------------------------------------------------------------------

def launch_ner_service(
    model_name: str,
    device: str,
    port: int,
    batch_size: int = 32,
    timeout: float = 180.0,
) -> multiprocessing.Process:
    """Start the NER service in a daemon subprocess and wait until it's ready.

    Returns the process handle so the caller can terminate it when done.
    Raises ``TimeoutError`` if the service does not become ready within *timeout* seconds.
    """
    proc = multiprocessing.Process(
        target=_run_server,
        args=(model_name, device, port, batch_size),
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

    # Give the process a moment to start, then check it hasn't immediately crashed
    # (e.g. port already in use from a previous run).
    time.sleep(1.0)
    if not proc.is_alive():
        raise RuntimeError(
            f"NER service process died immediately (exit code: {proc.exitcode}). "
            f"Port {port} may already be in use by a previous run. "
            f"Kill it with: fuser -k {port}/tcp"
        )

    _wait_for_ready(port, timeout)
    logger.info("NER service is ready on port %d", port)
    return proc


def _wait_for_ready(port: int, timeout: float) -> None:
    import httpx

    deadline = time.monotonic() + timeout
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
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
