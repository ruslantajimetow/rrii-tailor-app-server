from fastapi import APIRouter, Depends, HTTPException, status
from app.core.deps import get_curret_user
from app.schemas.user import (
    BindPhoneStartRequest,
    BindPhoneVerifyRequest,
    PhoneRequestOtp,
    PhoneVerifyOtp,
)
from app.services.twilio.service import send_verification_code, check_verification_code
from app.core.security import create_access_token
from app.db import get_db
from app.models.user import User, UserRole
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from app.schemas.user import (
    PhoneRequestOtp,
    PhoneVerifyOtp,
    TokenResponse,
)


router = APIRouter(tags=["phone"])


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

    user = db.query(User).filter(User.phone_number == payload.phone_number).first()

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


@router.post("/me/bind-phone-start")
async def bind_phone_start(
    payload: BindPhoneStartRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_curret_user),
):
    phone_owner = (
        db.query(User)
        .filter(
            User.phone_number == payload.phone_number, User.uuid != current_user.uuid
        )
        .first()
    )

    if phone_owner:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Phone number already bound to another user",
        )

    try:
        send_verification_code(payload.phone_number)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to send OTP: {e}",
        )

    return {
        "message": "Please check your phone for the verification code",
        "phone_number": payload.phone_number,
    }


@router.post("/me/bind-phone-verify")
async def bind_phone_verify(
    payload: BindPhoneVerifyRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_curret_user),
):

    verification_check = check_verification_code(payload.phone_number, payload.code)

    if verification_check.status != "approved":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired OTP",
        )

    current_user.is_phone_verified = True
    current_user.phone_number = payload.phone_number
    db.add(current_user)
    db.commit()
    db.refresh(current_user)

    return {
        "message": "Phone number successfully verified and linked to your account.",
        "phone_number": current_user.phone_number,
    }
