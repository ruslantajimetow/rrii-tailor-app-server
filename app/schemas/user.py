from uuid import UUID
from pydantic import BaseModel, Field, EmailStr


class PhoneSignupRequest(BaseModel):
    phone_number: str = Field(..., min_length=5, max_length=32)


class PhoneRequestOtp(BaseModel):
    phone_number: str = Field(..., min_length=5, max_length=32)


class PhoneVerifyOtp(BaseModel):
    phone_number: str = Field(..., min_length=5, max_length=32)
    code: str = Field(..., min_length=4, max_length=10)


class EmailRegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=6, max_length=128)


class EmailLoginRequest(BaseModel):
    email: EmailStr
    password: str


class EmailVerifyOtpRequest(BaseModel):
    email: EmailStr
    code: str = Field(..., min_length=4, max_length=10)


class BindEmailStartRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=6, max_length=128)


class BindEmailVerifyRequest(BaseModel):
    code: str = Field(..., min_length=4, max_length=10)


class BindPhoneStartRequest(BaseModel):
    phone_number: str = Field(..., min_length=5, max_length=32)


class BindPhoneVerifyRequest(BaseModel):
    phone_number: str = Field(..., min_length=5, max_length=32)
    code: str = Field(..., min_length=4, max_length=10)


class UserResponse(BaseModel):
    id: int
    uuid: UUID
    phone_number: str | None
    email: str | None
    role: str
    is_active: bool
    is_phone_verified: bool

    class Config:
        from_attributes = True


class TokenResponse(BaseModel):
    access_token: str
    token_type: str
    user: UserResponse
