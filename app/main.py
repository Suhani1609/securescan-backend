from dotenv import load_dotenv
load_dotenv()

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.routes.scan import router as scan_router
from app.routes.auth import router as auth_router
from app.routes.history import router as history_router

app = FastAPI(
    title="SecureScan API",
    description="Malware Detection Backend",
    version="1.0"
)

# Allow frontend (React) to access backend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def root():
    return {"status": "SecureScan backend running"}

# Include scan routes
app.include_router(scan_router, prefix="/api/scan", tags=["Scan"])
app.include_router(auth_router, prefix="/api/auth", tags=["Auth"])
app.include_router(history_router, prefix="/api/history", tags=["History"])

