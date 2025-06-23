from uuid import UUID
from sqlalchemy import update
from pydantic import EmailStr
from datetime import datetime, timedelta


from src.logs.logger import logger
from src.services import BaseRepository
from src.models import User, RefreshToken
from src.database import get_async_session


class UserRepository(BaseRepository[User]):
    """
    Репозиторий для выполнения CRUD-операций с моделью User.
    """
    model = User

    @classmethod
    async def ban(cls, user_email: EmailStr) -> User | None:
        """
        Устанавливает блокировку пользователя.

        Args:
            user_email: Email пользователя, которого нужно заблокировать.

        Returns:
            Обновлённый пользователь или None, если не найден.
        """
        async with get_async_session() as session:
            stmt = (
                update(cls.model)
                .where(cls.model.email == user_email)
                .values(ban_date=datetime.utcnow())
                .returning(cls.model)
            )
            result = await session.execute(stmt)
            await session.commit()
            return result.scalars().one_or_none()
        
    @classmethod
    async def unban(cls, user_email: EmailStr) -> User | None:
        """
        Снимает блокировку с пользователя.

        Args:
            user_email: Email пользователя, которого нужно разблокировать.

        Returns:
            Обновлённый пользователь или None, если не найден.
        """
        async with get_async_session() as session:
            stmt = (
                update(cls.model)
                .where(cls.model.email == user_email)
                .values(ban_date=None)
                .returning(cls.model)
            )
            result = await session.execute(stmt)
            await session.commit()
            return result.scalars().one_or_none()


    @classmethod
    async def update_last_activity(cls, user_email: EmailStr, min_interval_minutes: int = 30) -> bool:
        """
        Обновляет поле last_activity для пользователя, если с последнего обновления прошло достаточно времени.

        Args:
            user_id: ID пользователя.
            min_interval_minutes: Минимальный интервал в минутах между обновлениями (по умолчанию 30).

        Returns:
            bool: True, если обновление выполнено, False, если обновление не требовалось или произошла ошибка.
        """
        async with get_async_session() as session:
            query = (
                update(cls.model)
                .where(
                    cls.model.email == user_email,
                    (cls.model.last_activity.is_(None) | (cls.model.last_activity < datetime.utcnow() - timedelta(minutes=min_interval_minutes)))
                )
                .values(last_activity=datetime.utcnow())
                .returning(cls.model.id)
            )
            result = await session.execute(query)
            await session.commit()
            updated = result.scalars().one_or_none() is not None
            if updated:
                logger.info(f"Обновлено last_activity для пользователя с email {user_email}")
            return updated


class RefreshTokenRepository(BaseRepository[RefreshToken]):
    """
    Репозиторий для выполнения CRUD-операций с моделью RefreshToken.
    """
    model = RefreshToken

    @classmethod
    async def revoke(cls, jti: UUID, revoked: datetime) -> RefreshToken | None:
        """
        Отзывает refresh-токен, устанавливая дату отзыва.

        Args:
            jti: Уникальный идентификатор токена (JWT ID).
            revoked: Дата и время отзыва токена.

        Returns:
            Обновлённый экземпляр RefreshToken, если токен найден, иначе None.
        """
        async with get_async_session() as session:
            query = update(cls.model).where(cls.model.jti == jti).values(revoked=revoked).returning(cls.model)
            result = await session.execute(query)
            await session.commit()
            return result.scalars().one_or_none()
        

    @classmethod
    async def revoke_all_by_user_email(cls, email: str) -> int:
        """
        Отзывает все refresh-токены пользователя, устанавливая дату отзыва.

        Args:
            email: Email пользователя.

        Returns:
            Количество отозванных токенов.
        """
        async with get_async_session() as session:
            stmt = (
                update(cls.model)
                .where(cls.model.email == email, cls.model.revoked.is_(None))
                .values(revoked=datetime.now())
            )
            result = await session.execute(stmt)
            await session.commit()
            return result.rowcount
        