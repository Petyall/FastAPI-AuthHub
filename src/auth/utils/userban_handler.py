from pydantic import EmailStr

from src.models import User
from src.auth.services import UserRepository
from src.exceptions import UserNotFoundException, UserAlreadyHasBanException, UserHasNotBanException


class UserBanHandler:
    """
    Класс для управления блокировкой пользователей.

    Предоставляет метод для блокировки или разблокировки пользователя на основе email.
    """

    @classmethod
    async def change_ban_status(cls, email: EmailStr, should_ban: bool) -> User:
        """
        Изменяет статус блокировки пользователя.

        Выполняет поиск пользователя по email. В зависимости от значения `should_ban`:
        - если True, пользователь блокируется (если ещё не заблокирован);
        - если False, пользователь разблокируется (если был заблокирован).

        Args:
            email (EmailStr): Адрес электронной почты пользователя.
            should_ban (bool): Флаг, указывающий на требуемое действие. True — заблокировать, False — разблокировать.

        Returns:
            User: Обновлённый объект пользователя.

        Raises:
            UserNotFoundException: Если пользователь с таким email не найден.
            UserAlreadyHasBanException: Если попытаться заблокировать уже заблокированного пользователя.
            UserHasNotBanException: Если попытаться разблокировать пользователя, который не был заблокирован.
        """
        user = await UserRepository.find_one_or_none(email=email)
        if not user:
            raise UserNotFoundException(email)

        if should_ban:
            if user.ban_date:
                raise UserAlreadyHasBanException(email, user.ban_date)
            return await UserRepository.ban(email)
        else:
            if not user.ban_date:
                raise UserHasNotBanException(email)
            return await UserRepository.unban(email)


user_ban_handler = UserBanHandler()
