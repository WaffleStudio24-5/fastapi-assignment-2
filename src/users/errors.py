from src.common import CustomException

# password의 검증에 실패한 경우
class InvalidPasswordException(CustomException):
    def __init__(self):
        # super(): 부모 클래스 'CustomException'의 __init__을 이 값들로 실행해라
        # 부모 클래스가 이미 만들어둔 값 저장 로직을 그대로 재사용 가능
        super().__init__( 
            status_code=422,
            error_code="ERR_002",
            error_message="INVALID PASSWORD"
        )

# 요청 본문에서 필수값이 누락된 경우
class MissingValueException(CustomException): 
    def __init__(self):
        super().__init__(
            status_code=422,
            error_code="ERR_001",
            error_message="MISSING VALUE"
        )

# phone_number의 검증에 실패한 경우
class InvalidPhoneNumberException(CustomException):
    def __init__(self):
        super().__init__(
            status_code=422,
            error_code="ERR_003",
            error_message="INVALID PHONE NUMBER"
        )

# bio의 길이가 초과한 경우
class BioTooLongException(CustomException):
    def __init__(self):
        super().__init__(
            status_code=422,
            error_code="ERR_004",
            error_message="BIO TOO LONG"
        )

# 같은 이메일의 사용자가 DB에 이미 등록되어 있는 경우
class EmailAlreadyExistsException(CustomException):
    def __init__(self):
        super().__init__(
            status_code=409,
            error_code="ERR_005",
            error_message="EMAIL ALREADY EXISTS"
        )