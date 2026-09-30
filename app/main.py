from fastapi import FastAPI

from app.api.incidents import router as incidents_router

app = FastAPI(
    title="Cyber Incident Command Simulator",
    description=(
        "A defensive cybersecurity incident-response simulator "
        "for investigating synthetic security incidents."
    ),
    version="0.1.0",
)

app.include_router(incidents_router)


@app.get("/")
def root():
    return {
        "name": "Cyber Incident Command Simulator",
        "version": "0.1.0",
        "status": "operational",
    }


@app.get("/health")
def health():
    return {
        "status": "healthy",
    }