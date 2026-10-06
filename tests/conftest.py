import os
import sys
import tempfile

import pytest
from flask import g

# База и ключ для тестов задаются до импорта приложения
_tmpdir = tempfile.mkdtemp(prefix='psycho-test-')
os.environ['DATABASE_URL'] = 'sqlite:///' + os.path.join(_tmpdir, 'test.db')
os.environ['SECRET_KEY'] = 'test-secret'
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask_app import app as flask_app  # noqa: E402
from extensions import db  # noqa: E402
from models import Group, User  # noqa: E402
from schema import ensure_schema  # noqa: E402
from werkzeug.security import generate_password_hash  # noqa: E402

CSRF = 'test-csrf-token'
PASSWORD = 'Secret-pass-1'


@pytest.fixture()
def app(tmp_path):
    flask_app.config.update(TESTING=True, UPLOAD_FOLDER=str(tmp_path / 'uploads'))
    with flask_app.app_context():
        db.drop_all()
        ensure_schema()
        yield flask_app
        db.session.remove()


@pytest.fixture()
def make_user(app):
    def _make(username, role='student', full_name=None, group=None, password=PASSWORD, **extra):
        grp = None
        if group:
            grp = Group.query.filter_by(name=group).first() or Group(name=group, course=1)
            db.session.add(grp)
            db.session.flush()
        user = User(
            username=username,
            email=f'{username}@example.com',
            password=generate_password_hash(password),
            role=role,
            full_name=full_name if full_name is not None else f'Имя {username}',
            group_id=grp.id if grp else None,
            **extra,
        )
        db.session.add(user)
        db.session.commit()
        return user
    return _make


class Client:
    """Тестовый клиент, который сам подставляет CSRF-токен."""

    def __init__(self, app):
        self.c = app.test_client()
        with self.c.session_transaction() as s:
            s['_csrf_token'] = CSRF

    @staticmethod
    def _fresh():
        # Запросы в тестах переиспользуют контекст приложения фикстуры, а Flask-Login
        # кэширует пользователя в g — сбрасываем, чтобы клиенты не путались между собой.
        g.pop('_login_user', None)

    def get(self, url, **kw):
        self._fresh()
        return self.c.get(url, **kw)

    def post(self, url, data=None, csrf=True, **kw):
        self._fresh()
        data = dict(data or {})
        if csrf:
            data.setdefault('_csrf_token', CSRF)
        return self.c.post(url, data=data, **kw)

    def login(self, username, password=PASSWORD):
        return self.post('/login', {'username': username, 'password': password})


@pytest.fixture()
def client(app):
    return Client(app)


@pytest.fixture()
def login_as(app):
    def _login(user):
        c = Client(app)
        resp = c.login(user.username)
        assert resp.status_code == 302, resp.data[:500]
        return c
    return _login
