from uuid import uuid4
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, status, Request

from src.models import User
from src.config import settings
from src.logs.logger import logger
from src.limits.limiter import limiter
from src.auth.services import UserRepository
from src.auth.dependencies import get_current_user
from src.email.schemas.responses import MessageResponse
from src.email.schemas.requests import EmailConfirmationRequest
from src.email.utils.email_handler import email_handler
from src.exceptions import (
    UserNotFoundException,
    TooEarlyResendException,
    EmailAlreadyConfirmedException,
    InvalidOrExpiredEmailTokenException,
)


router = APIRouter(prefix="/email", tags=["Модуль работы с email"])


@router.post("/confirm", response_model=MessageResponse, status_code=status.HTTP_200_OK)
@limiter.limit("5/minute")
async def confirm_email(request: Request, data: EmailConfirmationRequest) -> MessageResponse:
    """
    Подтверждает email пользователя по предоставленному токену.

    Args:
        request: HTTP-запрос для контекста лимитера.
        data: Данные запроса, содержащие email и токен подтверждения.

    Returns:
        Сообщение об успешном подтверждении email.

    Raises:
        InvalidOrExpiredEmailTokenException: Если токен недействителен, истёк или пользователь не найден.
    """
    user = await UserRepository.find_one_or_none(email=data.email, confirmation_token=str(data.confirmation_token))
    if not user or user.email_confirmed:
        raise InvalidOrExpiredEmailTokenException

    created_at = user.confirmation_token_created_at
    if not created_at or datetime.now() - created_at > timedelta(hours=settings.EMAIL_CONFIRM_TOKEN_EXPIRE):
        raise InvalidOrExpiredEmailTokenException

    success = await UserRepository.update(
        id=user.id,
        email_confirmed=True,
        email_confirmed_at=datetime.now(),
        confirmation_token=None,
        confirmation_token_created_at=None,
    )

    if not success:
        logger.error(f"Ошибка при подтверждении email: не удалось обновить пользователя с email {data.email}")
        raise InvalidOrExpiredEmailTokenException()

    logger.info(f"Email пользователя {data.email} успешно подтверждён", extra={"log_info": True})

    return MessageResponse(message="Email успешно подтверждён")


@router.post("/resend", response_model=MessageResponse, status_code=status.HTTP_200_OK)
@limiter.limit("2/minute")
async def resend_confirmation(request: Request, current_user: User = Depends(get_current_user)) -> MessageResponse:
    """
    Повторно отправляет письмо для подтверждения email текущему пользователю.

    Args:
        request: HTTP-запрос для контекста лимитера.
        current_user: Текущий аутентифицированный пользователь, полученный через зависимость.

    Returns:
        Сообщение о том, что письмо отправлено повторно (или об ошибке).

    Raises:
        UserNotFoundException: Если пользователь не найден.
        EmailAlreadyConfirmedException: Если email уже подтверждён.
        TooEarlyResendException: Если токен ещё действителен и повторная отправка невозможна.
    """
    user = await UserRepository.find_one_or_none(email=current_user.email)

    if not user:
        raise UserNotFoundException

    if user.email_confirmed:
        raise EmailAlreadyConfirmedException

    created_at = user.confirmation_token_created_at
    if created_at and datetime.now() - created_at < timedelta(hours=settings.EMAIL_CONFIRM_TOKEN_EXPIRE):
        raise TooEarlyResendException

    new_token = str(uuid4())
    created_at = datetime.now()
    await UserRepository.update(id=user.id, confirmation_token=new_token, confirmation_token_created_at=created_at)

    try:
        link = f"{settings.FRONTEND_URL}/email/confirm?email={user.email}&token={new_token}"
        html_content = email_handler.render_template(
            "confirm_email.html",
            {"confirmation_link": link}
        )
        await email_handler.send_email(to=user.email, subject="Подтверждение регистрации", html_content=html_content)
    except Exception as e:
        logger.error(f"Ошибка отправки email для подтверждения регистрации ({user.email}): {type(e).__name__}: {e}")
        return MessageResponse(message="Если аккаунт существует, письмо отправлено повторно")

    logger.info(f"Письмо с подтверждением email отправлено пользователю {user.email}", extra={"log_info": True})

    return MessageResponse(message="Если аккаунт существует, письмо отправлено повторно")