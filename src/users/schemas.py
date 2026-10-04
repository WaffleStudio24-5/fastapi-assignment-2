import re

from pydantic import BaseModel, field_validator, EmailStr
from fastapi import HTTPException

from src.users.errors import (
    InvalidPasswordException,
    InvalidPhoneNumberException,
    BioLengthException,
)

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
            raise InvalidPasswordException()
        return v

    #new validator for phone number exception
    @field_validator("phone_number", mode="after")
    def validate_phone_number(cls, v):
        if re.fullmatch(r"010-\d{4}-\d{4}", v) is None:
            raise InvalidPhoneNumberException()
        return v

    @field_validator("bio", mode="after")
    def validate_bio(cls, v):
        if v is not None and len(v) > 500:
            raise BioLengthException()
        return v

class User(BaseModel):
    user_id: int
    email: EmailStr
    hashed_password: str
    name: str
    phone_number: str
    height: float
    bio: str | None = None

class UserResponse(BaseModel):
    user_id: int
    name: str
    email: EmailStr
    phone_number: str
    bio: str | None = None
    height: float
