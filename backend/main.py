"""
NeuroSploit v3 - FastAPI Main Application
"""
import asyncio
from contextlib import asynccontextmanager
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pathlib import Path

from backend.config import settings
from backend.db.database import init_db, close_db
from backend.api.v1 import scans, targets, prompts, reports, dashboard, vulnerabilities, settings as settings_router, agent, agent_tasks, scheduler, vuln_lab, terminal, sandbox, tradecraft, memory, traces, governance
from backend.api.websocket import manager as ws_manager


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler"""
    # Startup
    print(f"Starting {settings.APP_NAME} v{settings.APP_VERSION}")
    await init_db()
    print("Database initialized")

    # Seed built-in tradecraft TTPs
    try:
        from backend.api.v1.tradecraft import seed_builtin_tradecraft
        from backend.db.database import async_session_maker as _asm
        async with _asm() as seed_db:
            await seed_builtin_tradecraft(seed_db)
        print("Tradecraft TTPs seeded")
    except Exception as e:
        print(f"Tradecraft seed skipped: {e}")

    # Initialize scheduler
    try:
        import json
        config_path = Path(__file__).parent.parent / "config" / "config.json"
        if config_path.exists():
            with open(config_path) as f:
                config = json.load(f)
            from core.scheduler import ScanScheduler
            scan_scheduler = ScanScheduler(config)
            scan_scheduler.start()
            app.state.scheduler = scan_scheduler
            print(f"Scheduler initialized (enabled={scan_scheduler.enabled})")
        else:
            app.state.scheduler = None
    except Exception as e:
        print(f"Scheduler init skipped: {e}")
        app.state.scheduler = None

    # Cleanup orphan sandbox containers from previous crashes
    try:
        from core.container_pool import get_pool
        pool = get_pool()
        await pool.cleanup_orphans()
        print("Sandbox pool initialized (orphan cleanup done)")
    except Exception as e:
        print(f"Sandbox pool init skipped: {e}")

    yield

    # Shutdown
    # Destroy all per-scan sandbox containers
    try:
        from core.container_pool import get_pool
        await get_pool().cleanup_all()
        print("Sandbox containers cleaned up")
    except Exception:
        pass
    if hasattr(app.state, 'scheduler') and app.state.scheduler:
        app.state.scheduler.stop()
    print("Shutting down...")
    await close_db()


# Create FastAPI app
app = FastAPI(
    title=settings.APP_NAME,
    description="AI-Powered Penetration Testing Platform",
    version=settings.APP_VERSION,
    lifespan=lifespan,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API routers
app.include_router(scans.router, prefix="/api/v1/scans", tags=["Scans"])
app.include_router(targets.router, prefix="/api/v1/targets", tags=["Targets"])
app.include_router(prompts.router, prefix="/api/v1/prompts", tags=["Prompts"])
app.include_router(reports.router, prefix="/api/v1/reports", tags=["Reports"])
app.include_router(dashboard.router, prefix="/api/v1/dashboard", tags=["Dashboard"])
app.include_router(vulnerabilities.router, prefix="/api/v1/vulnerabilities", tags=["Vulnerabilities"])
app.include_router(settings_router.router, prefix="/api/v1/settings", tags=["Settings"])
app.include_router(agent.router, prefix="/api/v1/agent", tags=["AI Agent"])
app.include_router(agent_tasks.router, prefix="/api/v1/agent-tasks", tags=["Agent Tasks"])
app.include_router(scheduler.router, prefix="/api/v1/scheduler", tags=["Scheduler"])
app.include_router(vuln_lab.router, prefix="/api/v1/vuln-lab", tags=["Vulnerability Lab"])
app.include_router(terminal.router, prefix="/api/v1/terminal", tags=["Terminal Agent"])
app.include_router(sandbox.router, prefix="/api/v1/sandbox", tags=["Sandbox"])
app.include_router(tradecraft.router, prefix="/api/v1/tradecraft", tags=["Tradecraft"])
app.include_router(memory.router, prefix="/api/v1/memory", tags=["Persistent Memory"])
app.include_router(traces.router, prefix="/api/v1/traces", tags=["Traces"])
app.include_router(governance.router, prefix="/api/v1/governance", tags=["Governance"])


@app.get("/api/health")
async def health_check():
    """Health check endpoint with LLM status"""
    import os

    # Check LLM availability
    anthropic_key = os.getenv("ANTHROPIC_API_KEY", "")
    openai_key = os.getenv("OPENAI_API_KEY", "")

    llm_status = "not_configured"
    llm_provider = None

    if anthropic_key and anthropic_key not in ["", "your-anthropic-api-key"]:
        llm_status = "configured"
        llm_provider = "claude"
    elif openai_key and openai_key not in ["", "your-openai-api-key"]:
        llm_status = "configured"
        llm_provider = "openai"
    else:
        # Check AWS Bedrock availability
        try:
            import boto3
            sts = boto3.client('sts', region_name=os.getenv("AWS_BEDROCK_REGION", "us-east-1"))
            sts.get_caller_identity()
            llm_status = "configured"
            llm_provider = "bedrock"
        except Exception:
            pass

    return {
        "status": "healthy",
        "app": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "llm": {
            "status": llm_status,
            "provider": llm_provider,
            "message": "AI agent ready" if llm_status == "configured" else "Set an LLM API key (ANTHROPIC_API_KEY, OPENAI_API_KEY, GEMINI_API_KEY) or configure AWS Bedrock credentials to enable AI features"
        }
    }


@app.websocket("/ws/scan/{scan_id}")
async def websocket_scan(websocket: WebSocket, scan_id: str):
    """WebSocket endpoint for real-time scan updates"""
    await ws_manager.connect(websocket, scan_id)
    try:
        while True:
            # Keep connection alive and handle client messages
            data = await websocket.receive_text()
            # Handle client commands (pause, resume, etc.)
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket, scan_id)


# Serve static files (frontend) in production
frontend_build = Path(__file__).parent.parent / "frontend" / "dist"
if frontend_build.exists():
    app.mount("/assets", StaticFiles(directory=frontend_build / "assets"), name="assets")

    @app.get("/{full_path:path}")
    async def serve_frontend(full_path: str):
        """Serve frontend for all non-API routes"""
        file_path = frontend_build / full_path
        if file_path.exists() and file_path.is_file():
            return FileResponse(file_path)
        return FileResponse(frontend_build / "index.html")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "backend.main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.DEBUG
    )
