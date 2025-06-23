from pydantic import EmailStr

from src.models import User
from src.auth.services import UserRepository
from src.exceptions import UserNotFoundException, UserAlreadyHasBanException, UserHasNotBanException


class UserBanHandler:

    @classmethod
    async def change_ban_status(cls, email: EmailStr, should_ban: bool) -> User:
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