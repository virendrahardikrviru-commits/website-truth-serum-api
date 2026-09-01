from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
import os

load_dotenv()

app = FastAPI(
    title="Website Truth Serum API",
    description="Analyze websites for trustworthiness and AI-generated content",
    version="1.0.0"
)

# CORS setup - Allow specific origins for production
origins = [
    "https://websitetruthserum.com",
    "https://www.websitetruthserum.com",
    "http://localhost:5173",  # Local development
    "http://localhost:3000",   # Local development alternative
    "http://127.0.0.1:5173",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,  # In production, use specific domains instead of ["*"]
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "Accept"],
    expose_headers=["Content-Type"],
    max_age=600,
)

@app.get("/")
async def root():
    return {
        "message": "Website Truth Serum API",
        "status": "running",
        "version": "1.0.0"
    }

@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "message": "API is up and running"
    }

# Import and include routers
from app.routers import analyze
from app.routers import domain_intel  # 👈 NEW
app.include_router(analyze.router)
app.include_router(domain_intel.router)  # 👈 NEW

# Fail fast on an invalid SCORING_MODE at startup (fail-closed, never silently
# falls back to legacy). Evidence is the default; legacy is explicit rollback.
analyze.get_scoring_mode()