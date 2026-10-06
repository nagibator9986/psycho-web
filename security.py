"""
Безопасность: секретный ключ, CSRF, ограничение перебора паролей,
безопасный редирект после входа и проверка загружаемых картинок.
"""
import hmac
import os
import secrets
import uuid
from datetime import datetime, timedelta
from urllib.parse import urlparse

from flask import abort, request, session
from markupsafe import Markup, escape

from extensions import db
from models import LoginAttempt

CSRF_SESSION_KEY = '_csrf_token'
CSRF_FORM_FIELD = '_csrf_token'

# Ограничение перебора: не больше N неудачных попыток за окно
LOGIN_WINDOW = timedelta(minutes=15)
MAX_FAILS_PER_USERNAME = 8
MAX_FAILS_PER_IP = 30

IMAGE_SIGNATURES = {
    'png': (b'\x89PNG\r\n\x1a\n',),
    'jpg': (b'\xff\xd8\xff',),
    'jpeg': (b'\xff\xd8\xff',),
    'gif': (b'GIF87a', b'GIF89a'),
    'webp': (b'RIFF',),
}

# Пароли, которые когда-либо лежали в открытом виде в репозитории
LEAKED_PASSWORDS = ('Azamat65', 'changeme123')


# ---------- секретный ключ ----------

def load_secret_key(instance_path: str) -> str:
    """SECRET_KEY из окружения, иначе — случайный ключ, сохранённый в instance/."""
    key = os.environ.get('SECRET_KEY')
    if key:
        return key
    os.makedirs(instance_path, exist_ok=True)
    path = os.path.join(instance_path, 'secret_key')
    if os.path.exists(path):
        with open(path) as f:
            key = f.read().strip()
        if key:
            return key
    key = secrets.token_hex(32)
    try:
        # O_EXCL: если два процесса стартуют одновременно, файл создаст только один
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        with open(path) as f:
            return f.read().strip() or key
    with os.fdopen(fd, 'w') as f:
        f.write(key)
    return key


# ---------- CSRF ----------

def csrf_token() -> str:
    token = session.get(CSRF_SESSION_KEY)
    if not token:
        token = secrets.token_urlsafe(32)
        session[CSRF_SESSION_KEY] = token
    return token


def csrf_field() -> Markup:
    return Markup(
        f'<input type="hidden" name="{CSRF_FORM_FIELD}" value="{escape(csrf_token())}">'
    )


def _check_csrf():
    if request.method not in ('POST', 'PUT', 'PATCH', 'DELETE'):
        return
    expected = session.get(CSRF_SESSION_KEY)
    sent = request.form.get(CSRF_FORM_FIELD) or request.headers.get('X-CSRFToken')
    if not expected or not sent or not hmac.compare_digest(expected, sent):
        abort(400, description='csrf')


def init_security(app):
    app.before_request(_check_csrf)
    app.jinja_env.globals.update(csrf_token=csrf_token, csrf_field=csrf_field)


# ---------- вход ----------

def client_ip() -> str:
    forwarded = request.headers.get('X-Real-IP') or request.headers.get('X-Forwarded-For', '')
    ip = forwarded.split(',')[0].strip() if forwarded else ''
    return (ip or request.remote_addr or '')[:64]


def login_blocked(username: str, ip: str) -> bool:
    """
    Блокируем пару «логин + IP» и слишком активный IP. Только по логину не
    блокируем: иначе любой, кто знает чужой логин (ИИН), мог бы не пускать
    владельца в аккаунт.
    """
    since = datetime.utcnow() - LOGIN_WINDOW
    by_pair = LoginAttempt.query.filter(
        LoginAttempt.username == username.lower(),
        LoginAttempt.ip == ip,
        LoginAttempt.created_at >= since,
    ).count()
    if by_pair >= MAX_FAILS_PER_USERNAME:
        return True
    by_ip = LoginAttempt.query.filter(
        LoginAttempt.ip == ip, LoginAttempt.created_at >= since
    ).count()
    return by_ip >= MAX_FAILS_PER_IP


def record_failed_login(username: str, ip: str) -> None:
    db.session.add(LoginAttempt(username=username.lower()[:120], ip=ip))
    # заодно чистим старые записи
    LoginAttempt.query.filter(
        LoginAttempt.created_at < datetime.utcnow() - timedelta(days=1)
    ).delete()
    db.session.commit()


def clear_failed_logins(username: str, ip: str) -> None:
    LoginAttempt.query.filter_by(username=username.lower(), ip=ip).delete()
    db.session.commit()


def is_safe_next(target: str | None) -> bool:
    """Разрешаем редирект только на относительный путь этого же сайта."""
    if not target or not target.startswith('/') or target.startswith('//'):
        return False
    parsed = urlparse(target)
    return not parsed.scheme and not parsed.netloc and '\\' not in target


def password_problem(password: str) -> str | None:
    if len(password) < 8:
        return 'Пароль должен быть не короче 8 символов'
    if password.isdigit():
        return 'Пароль не должен состоять только из цифр'
    return None


# ---------- загрузка изображений ----------

def save_image(file_storage, folder: str) -> str:
    """
    Сохраняет картинку под случайным именем и возвращает имя файла.
    Принимает только png/jpg/gif/webp и проверяет сигнатуру файла,
    чтобы под видом картинки нельзя было загрузить html/svg/js.
    """
    original = file_storage.filename or ''
    ext = original.rsplit('.', 1)[-1].lower() if '.' in original else ''
    if ext not in IMAGE_SIGNATURES:
        raise ValueError('Допустимы только изображения PNG, JPG, GIF или WEBP')

    head = file_storage.stream.read(16)
    file_storage.stream.seek(0)
    if not any(head.startswith(sig) for sig in IMAGE_SIGNATURES[ext]):
        raise ValueError('Файл не похож на изображение')
    if ext == 'webp' and head[8:12] != b'WEBP':
        raise ValueError('Файл не похож на изображение')

    if ext == 'jpeg':
        ext = 'jpg'
    filename = f'{uuid.uuid4().hex}.{ext}'
    os.makedirs(folder, exist_ok=True)
    file_storage.save(os.path.join(folder, filename))
    return filename


def remove_upload(folder: str, filename: str | None) -> None:
    if not filename or '/' in filename or '\\' in filename:
        return
    try:
        os.remove(os.path.join(folder, filename))
    except OSError:
        pass
