from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from src.auth import auth_router

app = FastAPI()

# --- CORS Configuration ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows all origins for testing. Change to your domain in production.
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_router)