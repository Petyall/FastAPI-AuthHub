import jwt

from uuid import uuid4
from pathlib import Path
from datetime import datetime, timedelta
from pydantic import EmailStr, ValidationError

from src.config import settings
from src.auth.services import RefreshTokenRepository
from src.exceptions import (
    InvalidTokenException,
    ExpiredTokenException,
    InvalidEmailException,
)


class JWTHandler:
    """
    Класс для создания и проверки JWT-токенов.

    Использует приватный и публичный ключи для подписи и верификации токенов.
    Поддерживает создание access-токенов, refresh-токенов и токенов сброса пароля.
    """

    def __init__(self):
        # Загрузка приватного и публичного ключей шифрования из файлов
        self.private_key = Path(settings.JWT_PRIVATE_KEY_PATH).read_text()
        self.public_key = Path(settings.JWT_PUBLIC_KEY_PATH).read_text()

        # Конфигурация JWT из настроек приложения
        self.algorithm = settings.JWT_ALGORITHM
        self.access_token_exp = settings.JWT_ACCESS_TOKEN_EXPIRE
        self.refresh_token_exp = settings.JWT_REFRESH_TOKEN_EXPIRE
        self.reset_token_exp = settings.JWT_RESET_TOKEN_EXPIRE

    async def create_access_token(self, subject: EmailStr, pwd_reset_at: datetime) -> str:
        """
        Создаёт access-токен для аутентификации пользователя.

        Args:
            subject: Email пользователя, используемый как идентификатор.

        Returns:
            Подписанный JWT access-токен в виде строки.
        """
        token, _, _ = await self._create_token(subject, timedelta(minutes=self.access_token_exp), pwd_reset_at=pwd_reset_at)
        return token

    async def create_refresh_token(self, subject: str) -> str:
        """
        Создаёт refresh-токен и сохраняет его (jti, email, время истечения) в базе данных.

        Args:
            subject: Email пользователя, используемый как идентификатор.

        Returns:
            Подписанный JWT refresh-токен в виде строки.
        """
        token, jti, expires_at = await self._create_token(subject, timedelta(days=self.refresh_token_exp))
        await RefreshTokenRepository.add(jti=jti, email=subject, expires_at=expires_at)
        return token

    async def create_reset_token(self, subject: str) -> str:
        """
        Создаёт токен для сброса пароля.

        Args:
            subject: Email пользователя, используемый как идентификатор.

        Returns:
            Подписанный JWT токен сброса пароля в виде строки.
        """
        token, _, _ = await self._create_token(subject, timedelta(minutes=self.reset_token_exp))
        return token

    async def _create_token(self, email: str, expires_delta: timedelta, *, pwd_reset_at: datetime = None) -> tuple[str, str, datetime]:
        """
        Создаёт JWT-токен с указанным временем истечения.

        Args:
            email: Email пользователя для включения в payload токена.
            expires_delta: Длительность действия токена.

        Returns:
            Кортеж из подписанного токена, уникального идентификатора (jti) и времени истечения.

        Raises:
            InvalidEmailException: Если email имеет некорректный формат.
        """
        try:
            email = EmailStr._validate(email)
        except ValidationError:
            raise InvalidEmailException

        now = datetime.now()
        expire = now + expires_delta
        jti = str(uuid4())

        payload = {
            "sub": str(email),
            "iat": int(now.timestamp()),
            "exp": int(expire.timestamp()),
            "jti": jti,
        }

        if pwd_reset_at:
            payload["pwd_reset_at"] = int(pwd_reset_at.timestamp())

        token = jwt.encode(payload, self.private_key, algorithm=self.algorithm)
        return token, jti, expire

    async def decode_token(self, token: str) -> dict:
        """
        Декодирует и проверяет JWT-токен.

        Args:
            token: JWT-токен в виде строки.

        Returns:
            Словарь с payload токена, если токен действителен.

        Raises:
            ExpiredTokenException: Если срок действия токена истёк.
            InvalidTokenException: Если токен недействителен или не может быть декодирован.
        """
        try:
            payload = jwt.decode(token, self.public_key, algorithms=[self.algorithm])
            return payload
        except jwt.ExpiredSignatureError:
            raise ExpiredTokenException
        except jwt.InvalidTokenError:
            raise InvalidTokenException


jwt_handler = JWTHandler()
