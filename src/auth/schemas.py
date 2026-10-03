# BaseModel: Pydantic이 제공하는 "데이터 모양 틀"의 부모 클래스
# 이 클래스를 상속 받으면,
# 그 클래스는 자동으로 1) 필드가 빠지면 에러 2) 자료형이 틀리면 에러 능력을 가짐

# EmailStr: Pydantic이 추가로 제공하는 "이메일 모양 문자열" 자료형
from pydantic import BaseModel, EmailStr

# README의 로그인 요청은 다음처럼 생김
# { "email": "waffle@example.com", "password": "password1234" }

# 클래스를 만든다는 의미
# "필드 이름: 자료형"
class LoginRequest(BaseModel):
    email: EmailStr
    password: str