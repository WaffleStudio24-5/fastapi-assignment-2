import re
from pydantic import BaseModel, field_validator, EmailStr, StrictFloat
from fastapi import HTTPException
from src.users.errors import (
    InvalidPasswordException,
    InvalidPhoneNumberException,
    BioTooLongException,
)

class CreateUserRequest(BaseModel):
    name: str
    email: EmailStr
    password: str
    phone_number: str
    bio: str | None = None
    height: StrictFloat

    @field_validator('password', mode='after')
    def validate_password(cls, v):
        if len(v) < 8 or len(v) > 20:
            raise InvalidPasswordException()
        return v
    
    @field_validator('phone_number', mode='after')
    def validate_phone_number(cls, v):
        if re.fullmatch(r"010-[0-9]{4}-[0-9]{4}", v) is None:
            raise InvalidPhoneNumberException()
        return v

    @field_validator('bio', mode='after')
    def validate_bio(cls, v):
        if v is not None and len(v) > 500:
            raise BioTooLongException()
        return v

class UserResponse(BaseModel):
    user_id: int
    name: str
    email: EmailStr
    phone_number: str
    bio: str | None = None
    height: float
