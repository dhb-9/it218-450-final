from builtins import Exception
from fastapi import FastAPI, Depends
from starlette.responses import JSONResponse
from starlette.middleware.cors import CORSMiddleware
from sqlalchemy.ext.asyncio import AsyncSession
from app.database import Database
from app.dependencies import get_settings, get_email_service, get_db
from app.routers import user_routes
from app.services.user_service import UserService
from app.utils.api_description import getDescription

app = FastAPI(
    title="User Management",
    description=getDescription(),
    version="0.0.1",
    contact={
        "name": "API Support",
        "url": "http://www.example.com/support",
        "email": "support@example.com",
    },
    license_info={"name": "MIT", "url": "https://opensource.org/licenses/MIT"},
)

# CORS middleware configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # List of origins that are allowed to access the server, ["*"] allows all
    allow_credentials=True,  # Support credentials (cookies, authorization headers, etc.)
    allow_methods=["*"],  # Allowed HTTP methods
    allow_headers=["*"],  # Allowed HTTP headers
)

@app.on_event("startup")
async def startup_event():
    settings = get_settings()
    Database.initialize(settings.database_url, settings.debug)

@app.exception_handler(Exception)
async def exception_handler(request, exc):
    return JSONResponse(status_code=500, content={"message": "An unexpected error occurred."})

app.include_router(user_routes.router)

# Dependency to get the UserService
def get_user_service(db: AsyncSession = Depends(get_db)) -> UserService:
    return UserService
