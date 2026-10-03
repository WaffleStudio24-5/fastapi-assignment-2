# re: regular expression[정규 표현식]의 줄임말
# "이런 모양의 글자"를 규칙으로 적어서, 문자열이 그 모양인지 검사하는 방법 
import re 

from pydantic import BaseModel, field_validator, EmailStr
from fastapi import HTTPException

from src.users.errors import InvalidPasswordException, InvalidPhoneNumberException, BioTooLongException

class CreateUserRequest(BaseModel):
    name: str
    email: EmailStr
    password: str
    phone_number: str
    bio: str | None = None
    height: float

    # 자동 검증으로 부족한 부분을 우리가 추가하는 곳 
    @field_validator('password', mode='after')
    # cls: 클래스 자기 자신[CreateUserRequest) ; '클래스 전체'를 가리킴
    # 일반 메서드의 self: '객체 하나'를 가리킴 
    # v: 사용자가 보낸 값 
    def validate_password(cls, v):
        if len(v) < 8 or len(v) > 20:
            # 조건에 안 맞으면 raise 에러클래스()
            raise InvalidPasswordException()
        # 조건에 맞으면
        return v
    
    @field_validator('phone_number', mode='after')
    def validate_phone_number(cls, v):
        # r: raw하게 해석해라! 글자를 그냥 글자로 읽어라
        # \d: "숫자" 한 글자[0-9]
        # {4}: 바로 앞의 것을 4번 반복하라
        # \d{4}: 숫자 네 글자 
        # re.fullmatch: 1) 일치: 합격증[일치 객체] 2) NO일치: None 반환 
        if re.fullmatch(r"010-\d{4}-\d{4}", v) is None:
            raise InvalidPhoneNumberException()
        return v

    @field_validator('bio', mode='after')
    def validate_bio(cls, v):
        # and: 앞 조건이 거짓이면, 뒤는 아예 검사 안 함
        if v is not None and len(v) > 500:
            raise BioTooLongException()
        return v 

# 회원가입 성공 시 돌려줄 형태
# password는 포함하면 안됨!
class UserResponse(BaseModel):
    user_id: int
    name: str
    email: EmailStr
    phone_number: str
    bio: str | None = None
    height: float
