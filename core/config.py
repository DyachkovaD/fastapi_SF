import multiprocessing

from pydantic import PostgresDsn
from pydantic_core import MultiHostUrl
from pydantic_settings import BaseSettings

from calendar import timegm
from datetime import timedelta, datetime
import bcrypt
from jose import jwt
from passlib. context import CryptContext
from fastapi.security import OAuth2PasswordBearer


# специальный класс для настройки авторизации в Swagger
oauth2_bearer = OAuth2PasswordBearer(tokenUrl='/user/token')

class AppSettings(BaseSettings):
    app_port: int = 8010
    app_host: str = 'localhost'
    reload: bool = True
    cpu_count: int | None = None
    jwt_secret: str = "your_super_secret"
    algorithm: str = "HS256"

    postgres_dsn: PostgresDsn = MultiHostUrl(
    'postgresql+asyncpg://postgres:admin@localhost/fastapidb')
    class Config:
        _env_file = ".env"
        _extra = 'allow'


app_settings = AppSettings()

# набор опций для запуска сервера
uvicorn_options = {
    "host": app_settings.app_host,
    "port": app_settings.app_port,
    "workers": app_settings.cpu_count or multiprocessing.cpu_count(),
    "reload": app_settings.reload,

}

# Секретная фраза для генерации и валидации токенов
JWT_SECRET = app_settings.jwt_secret  # your_super_secret
# Алгоритм хеширования
ALGORITHM = app_settings.algorithm  # 'HS256'
# Контекст для валидации и хеширования
bcrypt_context = CryptContext(schemes=['bcrypt'], deprecated='auto')


# Генерация соли
def generate_salt():
    return bcrypt.gensalt().decode("utf-8")


# Хэширование пароля с использованием соли
def hash_password(password: str, salt: str):
    return bcrypt_context.hash(password + salt)


# Создание нового токена
def create_access_token(data: dict, expires_delta: timedelta = timedelta(minutes=15)) -> str:
    # копируем исходные данные, чтобы случайно их не испортить
    to_encode = data.copy()

    # устанавливаем временной промежуток жизни токена
    expire = timegm((datetime.utcnow() + expires_delta).utctimetuple())

    # добавляем время смерти токена
    to_encode.update({"exp": expire})

    # генерируем токен из данных, секрета и алгоритма
    return jwt.encode(to_encode, JWT_SECRET, algorithm=ALGORITHM)