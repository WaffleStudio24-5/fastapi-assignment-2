import re

from pydantic import BaseModel, field_validator, EmailStr
from fastapi import HTTPException
from pydantic_core import PydanticCustomError

from src.users.errors import InvalidPasswordException

class CreateUserRequest(BaseModel):
    name: str
    email: EmailStr
    password: str
    phone_number: str
    bio: str | None = None
    height: float

    @field_validator('password', mode='after')
    def validate_password(cls, v):
        if len(v) < 8 or len(v) > 20:
            raise PydanticCustomError(
            "invalid_password",
            "INVALID PASSWORD",
        )
        return v
    
    @field_validator('phone_number', mode='after')
    def validate_phone_number(cls, v):
        if re.fullmatch(r"010-\d{4}-\d{4}", v) is None:
            raise PydanticCustomError(
                "invalid_phone_number",
                "INVALID PHONE NUMBER",
            )
        return v

    @field_validator('bio', mode='after')
    def validate_bio(cls, v):
        if v is not None and len(v) > 500:
            raise PydanticCustomError(
                "bio_too_long",
                "BIO TOO LONG",
            )
        return v

class UserResponse(BaseModel):
    user_id: int
    name: str
    email: EmailStr
    phone_number: str
    bio: str | None = None
    height: float
