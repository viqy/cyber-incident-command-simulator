from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.api.incidents import router as incidents_router
from app.api.investigation import router as investigation_router
from app.database.database import initialize_database

from app.api.reporting import router as reporting_router


BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"


@asynccontextmanager
async def lifespan(app: FastAPI):
    initialize_database()
    yield


app = FastAPI(
    title="Cyber Incident Command Simulator",
    description=(
        "A defensive cybersecurity incident-response simulator "
        "for investigating synthetic security incidents."
    ),
    version="0.4.0",
    lifespan=lifespan,
)

app.include_router(incidents_router)
app.include_router(investigation_router)
app.include_router(reporting_router)



app.mount(
    "/static",
    StaticFiles(directory=STATIC_DIR),
    name="static",
)


@app.get("/", include_in_schema=False)
def root():
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/health")
def health():
    return {
        "status": "healthy",
    }