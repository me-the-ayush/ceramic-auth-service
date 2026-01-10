from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from src.auth import auth_router

app = FastAPI(
    title="Ceramic Auth Service",
    description="Microservice for Catalog, Cart, and Order Management",
    version="1.0.0",
)

# --- CORS Configuration ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows all origins for testing. Change to your domain in production.
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_router)

@app.get("/", tags=["Health"])
async def health_check():
    return {
        "status": "healthy",
        "service": "book-service",
        "environment": "production"
    }

if __name__ == "__main__":
    import uvicorn
    # Define your port here
    uvicorn.run(app, host="0.0.0.0", port=8080)