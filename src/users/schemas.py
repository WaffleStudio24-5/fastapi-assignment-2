import re

from pydantic import BaseModel, field_validator, EmailStr
from fastapi import HTTPException

from src.users.errors import InvalidPasswordException, InvalidPhoneNumberException, InvalidTokenException, InvalidAccountException, BioTooLongException, InvalidSessionException, UnauthenticatedException, BadAuthorizationHeaderException

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
    
    @field_validator('phone_number', mode='after')
    def validate_phone_number(cls, v):
        pn = r'010-\d{4}-\d{4}'
        if not re.fullmatch(pn, v):
            raise InvalidPhoneNumberException()
        return v

    @field_validator('bio', mode='after')
    def validate_bio(cls, v):
        if v != None:
            if len(v) > 500:
                raise BioTooLongException()
        return v

class UserResponse(BaseModel):
    user_id: int
    name: str
    email: EmailStr
    phone_number: str
    bio: str | None = None
    height: float
