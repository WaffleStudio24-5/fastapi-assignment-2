from src.common import CustomException

class InvalidAccountException(CustomException):
    def __init__(self):
        super().__init__(
            status_code=401,
            error_code="ERR_010",
            error_message="INVALID ACCOUNT",
        )
        
class UnauthenticatedException(CustomException):
    def __init__(self):
        super().__init__(
            status_code=401,
            error_code="ERR_009",
            error_message="UNAUTHENTICATED",
        )
        
class BadAuthorizationHeaderException(CustomException):
    def __init__(self):
        super().__init__(
            status_code=400,
            error_code="ERR_007",
            error_message="BAD AUTHORIZATION HEADER",
        )

class InvalidTokenException(CustomException):
    def __init__(self):
        super().__init__(
            status_code=401,
            error_code="ERR_008",
            error_message="INVALID TOKEN",
        )

class InvalidSessionException(CustomException):
    def __init__(self):
        super().__init__(
            status_code=401,
            error_code="ERR_006",
            error_message="INVALID SESSION",
        )