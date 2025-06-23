from datetime import date, datetime

from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy import Boolean, Date, DateTime, ForeignKey, String, Text

from src.database import Base


class Role(Base):
    __tablename__ = "roles"

    title: Mapped[str] = mapped_column(String(50), primary_key=True)

    users: Mapped[list["User"]] = relationship(back_populates="role")


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    password: Mapped[str] = mapped_column(String(512))
    registration_date: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow())
    last_activity: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    first_name: Mapped[str] = mapped_column(String(100), nullable=True)
    last_name: Mapped[str] = mapped_column(String(100), nullable=True)
    paternal_name: Mapped[str] = mapped_column(String(100), nullable=True)
    phone_number: Mapped[str] = mapped_column(String(20), nullable=True)
    birthday: Mapped[date] = mapped_column(Date, nullable=True)

    ban_date: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    role_title: Mapped[str] = mapped_column(ForeignKey("roles.title"))
    role: Mapped["Role"] = relationship(back_populates="users")

    email_confirmed: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")
    email_confirmed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    confirmation_token: Mapped[str | None] = mapped_column(Text, nullable=True)
    confirmation_token_created_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    refresh_tokens: Mapped[list["RefreshToken"]] = relationship(back_populates="user", cascade="all, delete-orphan")

    password_reset_token: Mapped[str | None] = mapped_column(String(), nullable=True)
    password_reset_token_created_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_password_reset: Mapped[datetime | None] = mapped_column(DateTime, nullable=True, default=datetime.utcnow())


class RefreshToken(Base):
    __tablename__ = "refresh_tokens"

    jti: Mapped[str] = mapped_column(String, primary_key=True, index=True)
    email: Mapped[str] = mapped_column(String(255), ForeignKey("users.email", ondelete="CASCADE"), index=True, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    revoked: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow())

    user: Mapped["User"] = relationship(back_populates="refresh_tokens")
