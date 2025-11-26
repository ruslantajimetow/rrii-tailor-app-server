from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from twilio.rest.routes.v2 import phone_number
from app.core.security import create_access_token, hash_password
from app.db import get_db
from app.models.user import User, UserRole
from app.schemas.user import (
    EmailRegisterRequest,
    EmailVerifyOtpRequest,
    PhoneRequestOtp,
    PhoneVerifyOtp,
    TokenResponse,
)
from app.services.sendgrid.service import send_email_otp
from app.services.twilio.service import send_verification_code, check_verification_code
import random
from datetime import datetime, timedelta, timezone


router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/phone/send-otp")
async def request_phone_otp(payload: PhoneRequestOtp):
    """
    Start phone verification by sending an OTP via Twilio.
    """
    try:
        send_verification_code(payload.phone_number)
        return {"message": "OTP sent (Twilio trial: only to verified numbers)."}
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to send OTP: {e}",
        )


@router.post("/phone/verify-otp", response_model=TokenResponse)
async def verify_phone_otp(payload: PhoneVerifyOtp, db: Session = Depends(get_db)):
    """
    Verify the OTP code sent to the phone number.
    """
    try:
        verification_check = check_verification_code(payload.phone_number, payload.code)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to verify OTP: {e}",
        )
    if verification_check.status != "approved":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired OTP"
        )

    user = db.query(User).filter(phone_number == payload.phone_number).first()

    if not user:
        user = User(
            phone_number=payload.phone_number,
            auth_provider="phone",
            role=UserRole.USER,
            is_active=True,
            is_phone_verified=True,
        )
        db.add(user)
    else:
        user.is_phone_verified = True
    try:
        # 5) Commit new user to DB
        db.commit()
    except IntegrityError:
        # 6) If another request already created the same phone in parallel
        db.rollback()
        # Try to load existing user instead
        existing = (
            db.query(User).filter(User.phone_number == payload.phone_number).first()
        )
        if not existing:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to create or fetch user after OTP verification.",
            )
        user = existing
    db.refresh(user)

    access_token = create_access_token(data={"sub": str(user.uuid)})
    return {"access_token": access_token, "token_type": "Bearer", "user": user}


@router.post("/email/register")
async def user_register(payload: EmailRegisterRequest, db: Session = Depends(get_db)):
    existing_user = db.query(User).filter(User.email == payload.email).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="User already exists"
        )
    hashed_password = hash_password(payload.password)
    email_otp_code = f"{random.randint(0, 999999):06d}"
    email_otp_expires_at = datetime.now(timezone.utc) + timedelta(minutes=10)

    user = User(
        email=payload.email,
        password_hash=hashed_password,
        auth_provider="email",
        role=UserRole.USER,
        is_active=True,
        is_email_verified=False,
        email_otp_code=email_otp_code,
        email_otp_expires_at=email_otp_expires_at,
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    try:
        send_email_otp(user)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to send email OTP: {e}",
        )

    return {
        "message": "Please check your email for the verification code",
        "email": user.email,
    }


@router.post("/email/verify-otp")
async def verify_email_otp(
    payload: EmailVerifyOtpRequest, db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.email == payload.email).first()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="User not found"
        )

    if not user.email_otp_code or not user.email_otp_expires_at:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Email OTP not found"
        )

    now_utc = datetime.now(timezone.utc)
    if user.email_otp_expires_at < now_utc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Email OTP expired"
        )

    if payload.code != user.email_otp_code:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid verification code.",
        )

    user.is_email_verified = True
    user.email_otp_code = None
    user.email_otp_expires_at = None

    db.commit()
    db.refresh(user)
    access_token = create_access_token(data={"sub": str(user.uuid)})
    return {"access_token": access_token, "token_type": "Bearer", "user": user}
