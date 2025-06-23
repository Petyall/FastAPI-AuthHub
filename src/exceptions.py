from fastapi import HTTPException, status


class ProjectException(HTTPException):
    status_code = 500
    detail = "Внутренняя ошибка сервера"
    expose_to_client: bool = True

    def __init__(self, detail: str = None, expose_to_client: bool = True):
        if detail:
            self.detail = detail
        self.expose_to_client = expose_to_client
        super().__init__(status_code=self.status_code, detail=self.detail)

# --- Ошибки, связанные с пользователями ---

class UserAlreadyExistsException(ProjectException):
    status_code = status.HTTP_409_CONFLICT

    def __init__(self, user_email: str):
        super().__init__(detail=f"Пользователь {user_email} уже зарегистрирован")


class UserNotFoundException(ProjectException):
    status_code = status.HTTP_404_NOT_FOUND

    def __init__(self, user_email: str):
        super().__init__(detail=f"Пользователь {user_email} не найден")


class UserHasNoRightsException(ProjectException):
    status_code = status.HTTP_403_FORBIDDEN
    detail = "Доступ запрещён"


class UserAlreadyHasBanException(ProjectException):
    status_code = status.HTTP_409_CONFLICT

    def __init__(self, user_email: str, ban_date: str):
        super().__init__(detail=f"Пользователь {user_email} уже имеет блокировку с {ban_date}")


class UserHasNotBanException(ProjectException):
    status_code = status.HTTP_409_CONFLICT

    def __init__(self, user_email: str):
        super().__init__(detail=f"У пользователя {user_email} нет блокировки")


class UserBannedException(ProjectException):
    status_code = status.HTTP_403_FORBIDDEN

    def __init__(self, ban_date: str):
        super().__init__(detail=f"Пользователь заблокирован с {ban_date.strftime('%Y-%m-%d %H:%M:%S')}")


class CannotBanSelfException(ProjectException):
    status_code = status.HTTP_409_CONFLICT
    detail = "Вы не можете заблокировать сами себя"


# --- Ошибки, связанные с паролем ---

class PasswordValidationErrorException(ProjectException):
    status_code = status.HTTP_400_BAD_REQUEST

    def __init__(self, validation_result: str):
        super().__init__(detail=f"Пароль не соответствует требованиям:\n{validation_result}")


class PasswordIdenticalToPreviousException(ProjectException):
    status_code = status.HTTP_400_BAD_REQUEST
    detail = "Пароль должен отличаться от предыдущего"

# --- Ошибки, связанные с токенами сброса пароля ---

class InvalidPasswordResetTokenException(ProjectException):
    status_code = status.HTTP_400_BAD_REQUEST
    detail = "Ссылка для сброса пароля недействительна"

# --- Ошибки, связанные с авторизацией и аутентификацией ---

class InvalidCredentialsException(ProjectException):
    status_code = status.HTTP_401_UNAUTHORIZED
    detail = "Неверные учётные данные"


class RefreshTokenNotFoundException(ProjectException):
    status_code = status.HTTP_401_UNAUTHORIZED
    detail = "Токен обновления не предоставлен"


class InvalidRefreshTokenException(ProjectException):
    status_code = status.HTTP_401_UNAUTHORIZED
    detail = "Недействительный токен обновления"


class AccessTokenNotFoundException(ProjectException):
    status_code = status.HTTP_401_UNAUTHORIZED
    detail = "Токен доступа не предоставлен"


class InvalidAccessTokenException(ProjectException):
    status_code = status.HTTP_401_UNAUTHORIZED
    detail = "Недействительный токен доступа"


class InvalidTokenException(ProjectException):
    status_code = status.HTTP_401_UNAUTHORIZED
    detail = "Неверный токен"


class ExpiredTokenException(ProjectException):
    status_code = status.HTTP_401_UNAUTHORIZED
    detail = "Токен просрочен"


class InvalidEmailException(ProjectException):
    status_code = status.HTTP_400_BAD_REQUEST
    detail = "Некорректный email"

# --- Ошибки, связанные с подтверждением email ---

class InvalidOrExpiredEmailTokenException(ProjectException):
    status_code = status.HTTP_400_BAD_REQUEST
    detail = "Ссылка подтверждения недействительна или устарела"


class EmailAlreadyConfirmedException(ProjectException):
    status_code = status.HTTP_400_BAD_REQUEST
    detail = "Почта уже подтверждена"


class TooEarlyResendException(ProjectException):
    status_code = status.HTTP_429_TOO_MANY_REQUESTS
    detail = "Слишком частые попытки. Попробуйте позже"

# --- Общие/внутренние ошибки ---

class InternalServerErrorException(ProjectException):
    status_code = status.HTTP_500_INTERNAL_SERVER_ERROR

    def __init__(self, reason: str = "Внутренняя ошибка сервера"):
        super().__init__(detail=reason, expose_to_client=False)
    