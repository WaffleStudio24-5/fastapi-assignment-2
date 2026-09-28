import re

from pydantic import BaseModel, EmailStr, Field, field_validator

from src.users.errors import (
    BioTooLongException,
    InvalidPasswordException,
    InvalidPhoneNumberException,
)


class CreateUserRequest(BaseModel):
    name: str
    email: EmailStr
    password: str
    phone_number: str
    height: float = Field(strict=True)
    bio: str | None = None

    @field_validator("password")
    @classmethod
    def validate_password(cls, value: str) -> str:
        if not 8 <= len(value) <= 20:
            raise InvalidPasswordException()
        return value

    @field_validator("phone_number")
    @classmethod
    def validate_phone_number(cls, value: str) -> str:
        if re.fullmatch(r"010-[0-9]{4}-[0-9]{4}", value) is None:
            raise InvalidPhoneNumberException()
        return value

    @field_validator("bio")
    @classmethod
    def validate_bio(cls, value: str | None) -> str | None:
        if value is not None and len(value) > 500:
            raise BioTooLongException()
        return value


class UserResponse(BaseModel):
    user_id: int
    name: str
    email: EmailStr
    phone_number: str
    height: float
    bio: str | None = None