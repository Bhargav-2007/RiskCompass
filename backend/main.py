"""
Main FastAPI Application for Dynamic Vulnerability Intelligence & Risk Scoring Platform
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
import uvicorn
import logging
from contextlib import asynccontextmanager

# Import API routes
from api.v1.routes import router as api_v1_router

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Application metadata
APP_TITLE = "Dynamic Vulnerability Intelligence & Risk Scoring Platform"
APP_DESCRIPTION = """
AI/ML-powered contextual risk scoring platform that shifts vulnerability prioritization 
away from static CVSS scores toward dynamic risk calculation based on organizational context.

Features:
- Dynamic risk scoring using XGBoost/LightGBM models
- Real-time threat intelligence integration
- Asset context and business impact quantification
- Predictive exploitability modeling
- Continuous reprioritization
- Risk analytics dashboard APIs
"""
APP_VERSION = "1.0.0"

# Application lifespan events
@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan events.
    Initialize resources on startup, cleanup on shutdown.
    """
    logger.info("Starting Dynamic Vulnerability Intelligence & Risk Scoring Platform")
    
    # Initialize database connections, load ML models, etc.
    # In practice: 
    # - Connect to PostgreSQL
    # - Load pre-trained ML models from disk
    # - Initialize Redis connection for caching
    # - Start background workers (Celery)
    
    yield
    
    logger.info("Shutting down platform")
    # Cleanup resources
    # - Close database connections
    # - Shutdown background workers

# Create FastAPI application
app = FastAPI(
    title=APP_TITLE,
    description=APP_DESCRIPTION,
    version=APP_VERSION,
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json"
)

# CORS middleware - configure origins as needed for production
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify actual origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Trusted host middleware - important for security
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=["*"]  # In production, specify actual hosts
)

# Include API routes
app.include_router(api_v1_router)

# Root endpoint
@app.get("/", tags=["root"])
async def root():
    """
    Root endpoint with platform information.
    """
    return {
        "message": "Welcome to the Dynamic Vulnerability Intelligence & Risk Scoring Platform",
        "version": APP_VERSION,
        "docs": "/docs",
        "health": "/api/v1/health"
    }

# Health check endpoint (also available in routes, but having it at app level too)
@app.get("/health", tags=["health"])
async def health_check():
    """
    Simple health check endpoint.
    """
    return {
        "status": "healthy",
        "timestamp": "2023-01-01T00:00:00Z",  # Would be actual timestamp
        "version": APP_VERSION
    }

# Run the application with Uvicorn when executed directly
if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,  # Set to False in production
        log_level="info"
    )