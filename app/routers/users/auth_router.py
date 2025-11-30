from fastapi import APIRouter
from app.routers.users import phone, email


router = APIRouter(prefix="/auth", tags=["auth"])
router.include_router(phone.router)
router.include_router(email.router)
