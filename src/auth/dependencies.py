from datetime import datetime
from fastapi import Depends, Request

from src.models import User
from src.auth.constants import UserRole
from src.auth.services import UserRepository
from src.auth.utils.jwt_handler import jwt_handler
from src.exceptions import (
    UserBannedException,
    UserNotFoundException,
    UserHasNoRightsException,
    InvalidAccessTokenException,
    AccessTokenNotFoundException,
    RefreshTokenNotFoundException,
)


async def get_access_token(request: Request) -> str:
    """
    Извлекает access-токен из cookies запроса.

    Args:
        request: HTTP-запрос, содержащий cookies.

    Returns:
        Access-токен в виде строки.

    Raises:
        AccessTokenNotFoundException: Если access-токен отсутствует в cookies.
    """
    access_token = request.cookies.get("access_token")
    if not access_token:
        raise AccessTokenNotFoundException
    return access_token


async def get_refresh_token(request: Request) -> str:
    """
    Извлекает refresh-токен из cookies запроса.

    Args:
        request: HTTP-запрос, содержащий cookies.

    Returns:
        Refresh-токен в виде строки.

    Raises:
        RefreshTokenNotFoundException: Если refresh-токен отсутствует в cookies.
    """
    refresh_token = request.cookies.get("refresh_token")
    if not refresh_token:
        raise RefreshTokenNotFoundException
    return refresh_token


async def get_current_user(token: str = Depends(get_access_token)) -> User:
    """
    Получает текущего пользователя на основе access-токена.

    Args:
        token: Access-токен, полученный из зависимости get_access_token.

    Returns:
        Экземпляр модели User, соответствующий пользователю.

    Raises:
        InvalidAccessTokenException: Если токен недействителен или не содержит email.
        UserNotFoundException: Если пользователь с указанным email не найден.
    """
    payload = await jwt_handler.decode_token(token)
    if not payload:
        raise InvalidAccessTokenException

    email = payload.get("sub")
    if not email:
        raise InvalidAccessTokenException

    user = await UserRepository.find_one_or_none(email=email)
    if not user:
        raise UserNotFoundException(email)
    
    if user.ban_date:
        raise UserBannedException(user.ban_date)

    pwd_reset_at_ts = payload.get("pwd_reset_at")
    if not pwd_reset_at_ts:
        raise InvalidAccessTokenException

    token_pwd_reset_at = datetime.fromtimestamp(pwd_reset_at_ts).replace(microsecond=0)
    user_pwd_reset_at = user.last_password_reset.replace(microsecond=0) if user.last_password_reset else None

    if user_pwd_reset_at and token_pwd_reset_at < user_pwd_reset_at:
        raise InvalidAccessTokenException


    return user


async def get_current_admin_user(user: User = Depends(get_current_user)) -> User:
    """
    Проверяет, является ли текущий пользователь администратором.

    Args:
        user: Пользователь, полученный из зависимости get_current_user.

    Returns:
        Экземпляр модели User, если пользователь имеет роль администратора.

    Raises:
        UserHasNoRightsException: Если пользователь не имеет роли администратора.
    """
    if user.role_title != UserRole.ADMIN.value:
        raise UserHasNoRightsException
    return user