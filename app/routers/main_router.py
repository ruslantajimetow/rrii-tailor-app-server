from fastapi import APIRouter
from app.routers.users.auth_router import router as auth_router

router = APIRouter(prefix="/api/v1", tags=["api"])
router.include_router(auth_router)
