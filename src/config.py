from pathlib import Path
from typing import Optional, Literal
from pydantic_settings import BaseSettings, SettingsConfigDict

from src.rsa_keygen import generate_rsa_key_pair


class Settings(BaseSettings):
    """
    Конфигурация приложения, загружаемая из переменных окружения или файла .env.

    Использует Pydantic для валидации и управления настройками.
    """
    model_config = SettingsConfigDict(env_file=".env")  # Загружает переменные из .env файла

    # --- Пароли ---
    PASSWORD_VALIDATION_LEVEL: Literal["none", "light", "medium", "strong"]  # Уровень строгости валидации паролей
    PASSWORDS_COMMON_LIST_PATH: str  # Путь к файлу со списком часто используемых паролей
    PASSWORD_BCRYPT_SALT_ROUNDS: int # Количество раундов при генерации соли для шифрования пароля

    # --- База данных ---
    DB_TYPE: str  # Тип базы данных (например, postgresql или sqlite)
    DB_HOST: Optional[str] = None  # Хост базы данных (опционально)
    DB_PORT: Optional[int] = None  # Порт базы данных (опционально)
    DB_USER: Optional[str] = None  # Пользователь базы данных (опционально)
    DB_PASS: Optional[str] = None  # Пароль для базы данных (опционально)
    DB_NAME: Optional[str] = None  # Имя базы данных (опционально)

    @property
    def DATABASE_URL(self) -> str:
        """
        Формирует строку подключения к базе данных на основе типа базы и параметров.

        Returns:
            Строка подключения для SQLAlchemy (например, postgresql+asyncpg://... или sqlite+aiosqlite://...).

        Raises:
            ValueError: Если для PostgreSQL не заданы все необходимые параметры или указан неизвестный тип базы данных.
        """
        if self.DB_TYPE == "postgresql":
            if not all([self.DB_HOST, self.DB_PORT, self.DB_USER, self.DB_PASS, self.DB_NAME]):
                raise ValueError("В файле .env заданы не все переменные окружения для PostgreSQL")
            return f"postgresql+asyncpg://{self.DB_USER}:{self.DB_PASS}@{self.DB_HOST}:{self.DB_PORT}/{self.DB_NAME}"
        elif self.DB_TYPE == "sqlite":
            return "sqlite+aiosqlite:///./db.sqlite3"
        else:
            raise ValueError(f"В файле .env указана неизвестная база данных (DB_TYPE): {self.DB_TYPE}")

    # --- JWT ---
    JWT_ALGORITHM: str  # Алгоритм подписи JWT-токенов
    JWT_ACCESS_TOKEN_EXPIRE: int  # Время жизни access-токена (в минутах)
    JWT_REFRESH_TOKEN_EXPIRE: int  # Время жизни refresh-токена (в минутах)
    JWT_RESET_TOKEN_EXPIRE: int  # Время жизни токена для сброса пароля (в минутах)
    JWT_PRIVATE_KEY_PATH: str  # Путь к файлу с приватным ключом для JWT
    JWT_PUBLIC_KEY_PATH: str  # Путь к файлу с публичным ключом для JWT

    # --- Email ---
    EMAIL_TEMPLATES: str  # Путь к шаблонам email-сообщений
    ENABLE_EMAIL_CONFIRMATION: bool  # Включение подтверждения по email
    EMAIL_CONFIRM_TOKEN_EXPIRE: int  # Время жизни токена подтверждения email (в минутах)
    EMAIL_FROM: str  # Адрес отправителя email
    SMTP_USERNAME: str  # Имя пользователя для SMTP-сервера
    SMTP_PASSWORD: str  # Пароль для SMTP-сервера
    SMTP_HOST: str  # Хост SMTP-сервера
    SMTP_PORT: int  # Порт SMTP-сервера

    # --- Frontend ---
    FRONTEND_URL: str  # URL фронтенд-приложения

    # --- Ограничения ---
    ENABLE_RATE_LIMITER: bool  # Включение ограничителя частоты запросов


# Проверка и генерация ключей при первом запуске
_env_file = Path(".env")
if _env_file.exists():
    from dotenv import dotenv_values
    env_vars = dotenv_values(_env_file)

    private_key_path = env_vars.get("JWT_PRIVATE_KEY_PATH")
    public_key_path = env_vars.get("JWT_PUBLIC_KEY_PATH")

    if private_key_path and public_key_path:
        if not Path(private_key_path).exists() or not Path(public_key_path).exists():
            generate_rsa_key_pair(private_key_path, public_key_path)


# Экземпляр настроек, инициализированный при загрузке модуля
settings = Settings()
