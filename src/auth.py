import os
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any, List
import asyncio
import httpx
from fastapi import Depends, HTTPException, status, APIRouter, Body
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt
from google.oauth2 import id_token
from google.auth.transport import requests as grequests
from dotenv import load_dotenv
from google.cloud import firestore
from src import db_utils
from fastapi import Request
from fastapi.responses import RedirectResponse
from urllib.parse import urlencode


load_dotenv()

# --- Configuration ---
SECRET_KEY = os.getenv("JWT_SECRET_KEY")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60
REFRESH_TOKEN_EXPIRE_DAYS = 30
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
FRONTEND_BASE_URL = os.getenv("FRONTEND_BASE_URL")
FRONTEND_AUTH_CALLBACK_PATH = os.getenv("FRONTEND_AUTH_CALLBACK_PATH")
FRONTEND_LOGIN_PATH = os.getenv("FRONTEND_LOGIN_PATH")

BACKEND_BASE_URL = os.getenv("BACKEND_BASE_URL")
BACKEND_GOOGLE_CALLBACK_PATH = os.getenv("BACKEND_GOOGLE_CALLBACK_PATH")

# --- FastAPI Router and Security Schemes ---
auth_router = APIRouter(prefix="/api/auth", tags=["auth"])
bearer_scheme = HTTPBearer(auto_error=True)
bearer_scheme_optional = HTTPBearer(auto_error=False)
oauth2_scheme = bearer_scheme
oauth2_scheme_optional = bearer_scheme_optional

# # --- Role Definitions ---
# ADMIN_ROLE = "admin"
# AUTHOR_ROLE = "author"
USER_ROLE = "user"



def create_access_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    """Creates a new JWT access token."""
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def create_refresh_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    """Creates a new JWT refresh token with a unique ID for revocation."""
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS))
    to_encode.update({"exp": expire, "jti": str(uuid.uuid4())})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt



async def verify_google_id_token(token: str) -> Dict[str, Any]:
    """Verifies the Google ID token and returns user information."""
    try:
        idinfo = id_token.verify_oauth2_token(token, grequests.Request(), GOOGLE_CLIENT_ID)
        if idinfo["iss"] not in ["accounts.google.com", "https://accounts.google.com"]:
            raise ValueError("Invalid issuer")
        return {
            "sub": idinfo["sub"],
            "email": idinfo["email"],
            "name": idinfo.get("name"),
            "picture": idinfo.get("picture"),
            "email_verified": idinfo.get("email_verified", False)
        }
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=f"Invalid Google token: {e}")



async def get_user_from_db(username: str) -> Optional[Dict[str, Any]]:
    return await db_utils.get_document("users", username)


# --- Auth Endpoints ---
@auth_router.get("/google/login")
async def google_oauth_login():
    params = {
        "client_id": GOOGLE_CLIENT_ID,
        "redirect_uri": f"{BACKEND_BASE_URL}{BACKEND_GOOGLE_CALLBACK_PATH}",
        "response_type": "code",
        "scope": "openid email profile",
        "access_type": "offline",
        "prompt": "consent",
    }

    google_auth_url = (
        "https://accounts.google.com/o/oauth2/v2/auth?"
        + urlencode(params)
    )

    return RedirectResponse(url=google_auth_url)

@auth_router.get("/google/callback")
async def google_oauth_callback(code: str):
    """
    Handles Google OAuth callback, creates JWT,
    and redirects back to frontend
    """
    try:
        # 1️⃣ Exchange authorization code for Google access token
        async with httpx.AsyncClient() as client:
            token_res = await client.post(
                "https://oauth2.googleapis.com/token",
                data={
                    "client_id": GOOGLE_CLIENT_ID,
                    "client_secret": GOOGLE_CLIENT_SECRET,
                    "code": code,
                    "grant_type": "authorization_code",
                    "redirect_uri": f"{BACKEND_BASE_URL}{BACKEND_GOOGLE_CALLBACK_PATH}",
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )

        token_res.raise_for_status()
        tokens = token_res.json()
        google_access_token = tokens["access_token"]

        # 2️⃣ Fetch Google user info
        async with httpx.AsyncClient() as client:
            userinfo_res = await client.get(
                "https://www.googleapis.com/oauth2/v3/userinfo",
                headers={"Authorization": f"Bearer {google_access_token}"},
            )

        userinfo_res.raise_for_status()
        user_info = userinfo_res.json()

        if not user_info.get("email_verified"):
            raise HTTPException(status_code=400, detail="Google email not verified")

        user_email = user_info["email"]

        # 3️⃣ Firestore user handling
        user_data = await get_user_from_db(user_email)

        if user_data is None:
            user_data = {
                "username": user_email,
                "name": user_info.get("name"),
                "picture": user_info.get("picture"),
                "roles": [USER_ROLE],
                "is_active": True,
                "google_id": user_info.get("sub"),
            }
            await db_utils.update_document("users", user_email, user_data)
        else:
            await db_utils.update_document(
                "users",
                user_email,
                {
                    "name": user_info.get("name"),
                    "picture": user_info.get("picture"),
                },
            )
            user_data.update(
                {
                    "name": user_info.get("name"),
                    "picture": user_info.get("picture"),
                }
            )

        # 4️⃣ Create JWT tokens
        access_token = create_access_token(
            {
                "sub": user_data["username"],
                "roles": user_data.get("roles", [USER_ROLE]),
                "is_active": user_data.get("is_active", True),
            }
        )

        refresh_token = create_refresh_token({"sub": user_data["username"]})
        refresh_payload = jwt.decode(refresh_token, SECRET_KEY, algorithms=[ALGORITHM])

        await db_utils.update_document(
            "users",
            user_data["username"],
            {
                "refresh_token_id": refresh_payload["jti"],
                "refresh_token_expires_at": datetime.fromtimestamp(
                    refresh_payload["exp"]
                ),
            },
        )

        # 5️⃣ Redirect back to frontend with JWT
        frontend_redirect = (
            f"{FRONTEND_BASE_URL}{FRONTEND_AUTH_CALLBACK_PATH}"
            f"?token={access_token}"
        )

        return RedirectResponse(url=frontend_redirect)

    except Exception as e:
        print("Google OAuth error:", e)

        # Fallback redirect to frontend login
        return RedirectResponse(
            url=f"{FRONTEND_BASE_URL}{FRONTEND_LOGIN_PATH}"
        )


@auth_router.post("/google-login")
async def google_login(access_token_str: str = Body(..., embed=True)):
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                "https://www.googleapis.com/oauth2/v3/userinfo",
                headers={"Authorization": f"Bearer {access_token_str}"}
            )
            response.raise_for_status()
            user_info = response.json()

            if not user_info.get("email_verified"):
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email not verified with Google")

    except httpx.HTTPStatusError as e:
        raise HTTPException(status_code=e.response.status_code,
                            detail=f"Invalid Google access token: {e.response.text}")
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Error fetching user info: {e}")

    user_email = user_info["email"]

    try:
        user_data = await get_user_from_db(user_email)

        updated_info = {
            "name": user_info.get("name"),
            "picture": user_info.get("picture")
        }

        if user_data is None:
            user_data = {
                "username": user_email,
                "name": user_info.get("name"),
                "picture": user_info.get("picture"),
                "roles": [USER_ROLE],
                "is_active": True,
                "google_id": user_info.get("sub"),
            }
            await db_utils.update_document("users", user_email, user_data)

        else:
            await db_utils.update_document("users", user_email, updated_info)
            user_data.update(updated_info)

    except Exception as e:
        print(f"Firestore operation failed during Google login for {user_email}: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                            detail="Login failed due to a server database error.")

    access_token_data = {
        "sub": user_data["username"],
        "roles": user_data.get("roles", [USER_ROLE]),
        "is_active": user_data.get("is_active", True)

    }
    access_token = create_access_token(access_token_data)

    refresh_token = create_refresh_token({"sub": user_data["username"]})

    refresh_token_payload = jwt.decode(refresh_token, SECRET_KEY, algorithms=[ALGORITHM])

    await db_utils.update_document(
        "users",
        user_data["username"],
        {
            "refresh_token_id": refresh_token_payload["jti"],
            "refresh_token_expires_at": datetime.fromtimestamp(refresh_token_payload["exp"])
        }
    )

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "user": user_data
    }


@auth_router.post("/refresh")
async def refresh_tokens(refresh_token_str: str = Body(..., embed=True)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate refresh token",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = jwt.decode(refresh_token_str, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        jti: str = payload.get("jti")
        if username is None or jti is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user = await get_user_from_db(username)
    if user is None:
        raise credentials_exception

    if user.get("refresh_token_id") != jti:
        raise credentials_exception

    expires_at = datetime.fromtimestamp(payload["exp"], tz=timezone.utc)
    if datetime.now(timezone.utc) > expires_at:
        raise credentials_exception

    new_access_token_data = {
        "sub": user["username"],
        "roles": user.get("roles", [USER_ROLE])
    }
    new_access_token = create_access_token(new_access_token_data)

    new_refresh_token = create_refresh_token({"sub": username})

    new_refresh_token_payload = jwt.decode(new_refresh_token, SECRET_KEY, algorithms=[ALGORITHM])
    await db_utils.update_document(
        "users",
        username,
        {
            "refresh_token_id": new_refresh_token_payload["jti"],
            "refresh_token_expires_at": datetime.fromtimestamp(new_refresh_token_payload["exp"])
        }
    )

    return {
        "access_token": new_access_token,
        "refresh_token": new_refresh_token,
        "token_type": "bearer"
    }