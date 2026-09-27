from src.common import CustomException


class InvalidSessionException(CustomException):
    def __init__(self):
        super().__init__(401, "ERR_006", "INVALID SESSION")


class BadAuthorizationHeaderException(CustomException):
    def __init__(self):
        super().__init__(400, "ERR_007", "BAD AUTHORIZATION HEADER")


class InvalidTokenException(CustomException):
    def __init__(self):
        super().__init__(401, "ERR_008", "INVALID TOKEN")


class UnauthenticatedException(CustomException):
    def __init__(self):
        super().__init__(401, "ERR_009", "UNAUTHENTICATED")


class InvalidAccountException(CustomException):
    def __init__(self):
        super().__init__(401, "ERR_010", "INVALID ACCOUNT")

        