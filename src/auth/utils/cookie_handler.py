from fastapi.responses import JSONResponse
from src.config import settings


class CookieHandler:
    """
    Класс для управления установкой аутентификационных токенов в cookies.

    Предоставляет методы для безопасной установки access и refresh-токенов в HTTP-ответ.
    """

    def __init__(self, access_token_expire: int = settings.JWT_ACCESS_TOKEN_EXPIRE, refresh_token_expire: int = settings.JWT_REFRESH_TOKEN_EXPIRE):
        self.access_token_expire = access_token_expire
        self.refresh_token_expire = refresh_token_expire

    def set_auth_tokens(self, response: JSONResponse, access_token: str, refresh_token: str) -> None:
        """
        Устанавливает access и refresh-токены в cookies ответа.
        Токены устанавливаются с флагами httponly, secure и samesite для повышения безопасности.
        Время жизни cookies соответствует настройкам JWT_ACCESS_TOKEN_EXPIRE и JWT_REFRESH_TOKEN_EXPIRE.

        Args:
            response: JSONResponse объект для установки cookies.
            access_token: Access-токен для аутентификации.
            refresh_token: Refresh-токен для обновления access-токена.
        """
        response.set_cookie(
            key="access_token",
            value=access_token,
            httponly=True,
            secure=True,
            samesite="Lax",
            max_age=self.access_token_expire * 60,
        )
        response.set_cookie(
            key="refresh_token",
            value=refresh_token,
            httponly=True,
            secure=True,
            samesite="Lax",
            max_age=self.refresh_token_expire * 60 * 60 * 24,
        )

cookie_handler = CookieHandler()
