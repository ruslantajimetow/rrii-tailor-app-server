from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.core.security import create_access_token, hash_password, verify_password
from app.db import get_db
from app.models.user import User, UserRole
from app.schemas.user import (
    BindEmailStartRequest,
    BindEmailVerifyRequest,
    EmailLoginRequest,
    EmailRegisterRequest,
    EmailVerifyOtpRequest,
    TokenResponse,
)
from app.services.sendgrid.service import send_email_otp
import random
from datetime import datetime, timedelta, timezone
from app.core.deps import get_curret_user

router = APIRouter(tags=["email"])


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


@router.post("/email/login", response_model=TokenResponse)
async def email_login(payload: EmailLoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == payload.email).first()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="user not found",
        )

    if not verify_password(payload.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid password",
        )

    access_token = create_access_token(data={"sub": str(user.uuid)})
    return {"access_token": access_token, "token_type": "Bearer", "user": user}


@router.post("/me/bind-email-start")
async def bind_email_start(
    payload: BindEmailStartRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_curret_user),
):

    email_owner = (
        db.query(User)
        .filter(User.email == payload.email, User.uuid != current_user.uuid)
        .first()
    )

    if email_owner:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already bound to another user",
        )

    hashed_password = hash_password(payload.password)

    email_otp_code = f"{random.randint(0, 999999):06d}"
    email_otp_expires_at = datetime.now(timezone.utc) + timedelta(minutes=10)

    current_user.email = payload.email
    current_user.password_hash = hashed_password
    current_user.email_otp_code = email_otp_code
    current_user.email_otp_expires_at = email_otp_expires_at
    current_user.is_email_verified = False

    db.add(current_user)
    db.commit()
    db.refresh(current_user)

    try:
        send_email_otp(current_user)
    except Exception as e:
        print(f"Failed to send email OTP: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to send email OTP: {e}",
        )

    return {
        "message": "Please check your email for the verification code",
        "email": current_user.email,
    }


@router.post("/me/bind-email-verify")
async def bind_email_verify(
    payload: BindEmailVerifyRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_curret_user),
):
    if not current_user.email_otp_code or not current_user.email_otp_expires_at:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No email verification code pending for this user.",
        )

    now_utc = datetime.now(timezone.utc)
    if current_user.email_otp_expires_at < now_utc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Verification code has expired.",
        )

    if payload.code != current_user.email_otp_code:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid verification code.",
        )

    current_user.is_email_verified = True
    current_user.email_otp_code = None
    current_user.email_otp_expires_at = None

    db.add(current_user)
    db.commit()
    db.refresh(current_user)

    return {
        "message": "Email successfully verified and linked to your account.",
        "email": current_user.email,
    }
