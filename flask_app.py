import csv
import hmac
import io
import logging
import os
import re
import secrets
from datetime import datetime, timedelta
from functools import wraps

import click
from flask import (
    Flask,
    Response,
    abort,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    send_file,
    url_for,
)
from flask_login import current_user, login_required, login_user, logout_user
from sqlalchemy import func, or_
from sqlalchemy.orm import joinedload
from werkzeug.exceptions import HTTPException
from werkzeug.security import check_password_hash, generate_password_hash

# общий db и login_manager
from extensions import db, login_manager
from models import (
    AnonThread,
    Appointment,
    Article,
    Comment,
    Group,
    Meeting,
    MeetingProtocol,
    Message,
    Post,
    Question,
    QuestionOption,
    StudentReport,
    Test,
    TestAnswer,
    TestInterpretation,
    TestResult,
    TestScaleOption,
    TestSubscale,
    User,
)
import pdf_utils
import security
import services
from schema import ensure_schema
from services import (
    APPOINTMENT_STATUSES,
    DEFAULT_SCALE,
    QUESTION_TYPES,
    TEST_TYPES,
    now_local,
    utc_to_local,
)

log = logging.getLogger(__name__)

# =========================
#       APP INIT
# =========================

app = Flask(__name__)


def _env_flag(name: str, default: bool = False) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in ('1', 'true', 'yes', 'on')


app.config.update(
    SECRET_KEY=security.load_secret_key(app.instance_path),
    # относительный путь Flask-SQLAlchemy кладёт в instance/ → instance/psych_help.db
    SQLALCHEMY_DATABASE_URI=os.environ.get('DATABASE_URL', 'sqlite:///psych_help.db'),
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    # пути от корня приложения, а не от текущего каталога процесса
    UPLOAD_FOLDER=os.path.join(app.root_path, 'static', 'uploads'),
    MAX_CONTENT_LENGTH=5 * 1024 * 1024,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=_env_flag('SESSION_COOKIE_SECURE'),
    REMEMBER_COOKIE_HTTPONLY=True,
    REMEMBER_COOKIE_SAMESITE='Lax',
    REMEMBER_COOKIE_SECURE=_env_flag('SESSION_COOKIE_SECURE'),
    REMEMBER_COOKIE_DURATION=timedelta(days=14),
    # Казахстан с 01.03.2024 живёт по UTC+5
    APP_UTC_OFFSET_HOURS=int(os.environ.get('APP_UTC_OFFSET_HOURS', '5')),
    SUPPORT_EMAIL=os.environ.get('SUPPORT_EMAIL', ''),
    SUPPORT_PHONE=os.environ.get('SUPPORT_PHONE', ''),
    ORG_NAME=os.environ.get('ORG_NAME', ''),
)

db.init_app(app)

login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Войдите, чтобы открыть эту страницу'
login_manager.login_message_category = 'info'

security.init_security(app)


@login_manager.user_loader
def load_user(user_id: str):
    uid, _, token = (user_id or '').partition(':')
    try:
        user = db.session.get(User, int(uid))
    except (TypeError, ValueError):
        return None
    if user is None or not token or not hmac.compare_digest(user.session_token, token):
        return None
    return user


# Результаты, сохранённые старой версией без заданной интерпретации, получали
# этот текст. Он вводил в заблуждение: для шкал депрессии и буллинга высокий
# балл — это не «норма».
LEGACY_FALLBACK_TEXTS = (
    'Низкий уровень. Рекомендуется консультация психолога.',
    'Средний уровень. Есть некоторые проблемы, но в целом ситуация под контролем.',
    'Высокий уровень. Ваше психологическое состояние в норме.',
)


def _fix_legacy_result_texts() -> int:
    fixed = 0
    tests = {}
    for result in TestResult.query.filter(TestResult.result_text.in_(LEGACY_FALLBACK_TEXTS)).all():
        test = tests.get(result.test_id) or db.session.get(Test, result.test_id)
        if test is None:
            continue
        tests[result.test_id] = test
        result.result_text = services.interpretation_text(test, result.score or 0)
        fixed += 1
    if fixed:
        db.session.commit()
    return fixed


def _revoke_leaked_passwords() -> list[str]:
    """
    Пароли из LEAKED_PASSWORDS лежали в публичном репозитории. Если служебный
    аккаунт всё ещё с таким паролем, сбрасываем его на случайный: войти по
    известному паролю больше нельзя, новый задаётся командой
    `flask --app flask_app set-password <логин>`.
    """
    revoked = []
    staff = User.query.filter(User.role.in_(('superadmin', 'admin', 'psychologist'))).all()
    for user in staff:
        if any(check_password_hash(user.password, p) for p in security.LEAKED_PASSWORDS):
            user.password = generate_password_hash(secrets.token_urlsafe(32))
            user.must_change_password = True
            revoked.append(user.username)
    if revoked:
        db.session.commit()
    return revoked


def _bootstrap_superadmin() -> None:
    """Первый суперадмин из переменных окружения (только если суперадминов нет)."""
    username = os.environ.get('INITIAL_SUPERADMIN_USERNAME')
    password = os.environ.get('INITIAL_SUPERADMIN_PASSWORD')
    if not username or not password:
        return
    if User.query.filter_by(role='superadmin').first():
        return
    email = os.environ.get('INITIAL_SUPERADMIN_EMAIL', f'{username}@localhost')
    user = User.query.filter(or_(User.username == username, User.email == email)).first()
    if user is None:
        user = User(username=username, email=email, full_name='Super Admin')
        db.session.add(user)
    user.role = 'superadmin'
    user.password = generate_password_hash(password)
    db.session.commit()
    log.warning('Создан суперадмин %s из переменных окружения', username)


def init_database() -> None:
    added = ensure_schema()
    if added:
        log.warning('Схема БД дополнена: %s', ', '.join(added))
    fixed = _fix_legacy_result_texts()
    if fixed:
        log.warning('Исправлен текст интерпретации у %s результатов', fixed)
    revoked = _revoke_leaked_passwords()
    if revoked:
        log.warning(
            'Пароли аккаунтов %s совпадали с опубликованными в репозитории и сброшены. '
            'Задайте новые: flask --app flask_app set-password <логин>', ', '.join(revoked)
        )
    _bootstrap_superadmin()


with app.app_context():
    init_database()

# подключаем админ-панель
from admin import admin_bp  # noqa: E402

app.register_blueprint(admin_bp)

# =========================
#       HELPERS
# =========================


def is_psychologist() -> bool:
    return current_user.is_authenticated and current_user.role == 'psychologist'


def is_student() -> bool:
    return current_user.is_authenticated and current_user.role == 'student'


def is_admin_user() -> bool:
    return current_user.is_authenticated and current_user.role in ('admin', 'superadmin')


def get_current_user():
    return current_user if current_user.is_authenticated else None


def roles_required(*roles):
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if not current_user.is_authenticated:
                return login_manager.unauthorized()
            if current_user.role not in roles:
                abort(403)
            return view(*args, **kwargs)
        return wrapped
    return decorator


def get_or_404(model, ident):
    obj = db.session.get(model, ident)
    if obj is None:
        abort(404)
    return obj


def own_test_or_403(test_id: int) -> Test:
    test = get_or_404(Test, test_id)
    if not is_psychologist() or test.user_id != current_user.id:
        abort(403)
    return test


def form_str(name: str, max_len: int | None = None) -> str:
    value = (request.form.get(name) or '').strip()
    return value[:max_len] if max_len else value


def form_int(name: str, default=None):
    try:
        return int((request.form.get(name) or '').strip())
    except ValueError:
        return default


def redirect_back(default_endpoint: str = 'index', **values):
    target = request.form.get('next') or request.args.get('next')
    if security.is_safe_next(target):
        return redirect(target)
    return redirect(url_for(default_endpoint, **values))


def _fmt_ts(value, fmt='%d.%m.%Y %H:%M'):
    """Время из базы в UTC (created_at) → местное."""
    local = utc_to_local(value)
    return local.strftime(fmt) if local else ''


def _fmt_when(value, fmt='%d.%m.%Y %H:%M'):
    """Время, введённое пользователем (дата встречи) — уже местное."""
    return value.strftime(fmt) if value else ''


def asset_url(filename: str) -> str:
    """Ссылка на статический файл с версией по времени изменения — браузер не держит старый CSS."""
    try:
        version = int(os.path.getmtime(os.path.join(app.static_folder, filename)))
    except OSError:
        version = 0
    return url_for('static', filename=filename, v=version)


def _greeting_name(user) -> str:
    """Имя для приветствия: из «Фамилия Имя Отчество» — имя, иначе как записано."""
    parts = (user.full_name or '').split()
    if len(parts) >= 3:
        return parts[1]
    return user.display_name


app.jinja_env.filters.update(ts=_fmt_ts, when=_fmt_when, greeting_name=_greeting_name)
app.jinja_env.globals.update(
    get_current_user=get_current_user,
    is_psychologist=is_psychologist,
    is_student=is_student,
    is_admin_user=is_admin_user,
    now_local=now_local,
    asset_url=asset_url,
    APPOINTMENT_STATUSES=APPOINTMENT_STATUSES,
    QUESTION_TYPES=QUESTION_TYPES,
    TEST_TYPES=TEST_TYPES,
    ROLE_NAMES={
        'student': 'Студент',
        'psychologist': 'Психолог',
        'admin': 'Администратор',
        'superadmin': 'Суперадмин',
    },
)


@app.context_processor
def inject_site():
    return {
        'current_year': now_local().year,
        'support_email': app.config['SUPPORT_EMAIL'],
        'support_phone': app.config['SUPPORT_PHONE'],
        'org_name': app.config['ORG_NAME'],
    }


@app.before_request
def enforce_password_change():
    if not current_user.is_authenticated or not current_user.must_change_password:
        return None
    if request.endpoint in ('change_password', 'logout', 'static', 'unread_messages_count'):
        return None
    flash('Задайте новый пароль, чтобы продолжить работу', 'warning')
    return redirect(url_for('change_password'))


# =========================
#       ERRORS
# =========================


@app.errorhandler(HTTPException)
def handle_http_error(error):
    if error.code == 400 and error.description == 'csrf':
        flash('Страница устарела. Обновите её и повторите действие.', 'warning')
        referrer = request.referrer or ''
        host = request.host_url
        if referrer.startswith(host):
            return redirect(referrer)
        return redirect(url_for('index'))
    if request.path.startswith('/api/'):
        return jsonify({'error': error.name}), error.code
    messages = {
        403: 'У вас нет доступа к этой странице.',
        404: 'Страница не найдена.',
        405: 'Такое действие здесь недоступно.',
        413: 'Файл слишком большой. Максимальный размер — 5 МБ.',
    }
    return render_template(
        'error.html',
        code=error.code,
        message=messages.get(error.code, error.description or error.name),
    ), error.code


@app.errorhandler(500)
def handle_server_error(error):
    db.session.rollback()
    return render_template(
        'error.html', code=500, message='Что-то пошло не так. Попробуйте ещё раз чуть позже.'
    ), 500


# =========================
#       CLI
# =========================


@app.cli.command('create-superadmin')
@click.argument('username')
@click.argument('email')
@click.password_option()
def create_superadmin_command(username, email, password):
    """Создать суперадмина (или сделать суперадмином существующего)."""
    problem = security.password_problem(password)
    if problem:
        raise click.ClickException(problem)
    user = User.query.filter(or_(User.username == username, User.email == email.lower())).first()
    if user is None:
        user = User(username=username, email=email.lower(), full_name='Super Admin')
        db.session.add(user)
    user.role = 'superadmin'
    user.password = generate_password_hash(password)
    user.must_change_password = False
    db.session.commit()
    click.echo(f'Готово: {username} — суперадмин')


@app.cli.command('set-password')
@click.argument('username')
@click.password_option()
def set_password_command(username, password):
    """Задать пароль пользователю."""
    user = User.query.filter_by(username=username).first()
    if user is None:
        raise click.ClickException('Пользователь не найден')
    problem = security.password_problem(password)
    if problem:
        raise click.ClickException(problem)
    user.password = generate_password_hash(password)
    user.must_change_password = False
    db.session.commit()
    click.echo(f'Пароль пользователя {username} обновлён')


@app.cli.command('audit-default-passwords')
@click.option('--apply', is_flag=True, help='Пометить найденных: сменить пароль при входе')
def audit_default_passwords_command(apply):
    """Найти студентов с паролем по шаблону «логин + abc» (так выдавал старый импорт)."""
    users = User.query.filter_by(role='student', must_change_password=False).all()
    found = 0
    with click.progressbar(users, label='Проверка паролей') as bar:
        for user in bar:
            if check_password_hash(user.password, f'{user.username}abc'):
                found += 1
                if apply:
                    user.must_change_password = True
    if apply:
        db.session.commit()
    click.echo(f'Пароль по шаблону у {found} из {len(users)} студентов.'
               + ('' if apply else ' Запустите с --apply, чтобы потребовать смену пароля.'))


# =========================
#         ROUTES
# =========================


@app.route('/')
def index():
    posts = []
    if current_user.is_authenticated:
        posts = Post.query.order_by(Post.created_at.desc()).limit(3).all()
    psychologists = (
        User.query.filter_by(role='psychologist').order_by(func.random()).limit(3).all()
    )
    articles = Article.query.order_by(Article.created_at.desc()).limit(3).all()
    return render_template(
        'index.html',
        posts=posts,
        psychologists=psychologists,
        articles=articles,
    )


# ---------- AUTH ----------

USERNAME_RE = re.compile(r'^[A-Za-z0-9_.\-]{3,80}$')
EMAIL_RE = re.compile(r'^[^@\s]+@[^@\s]+\.[^@\s]+$')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    all_groups = Group.query.order_by(Group.course.asc(), Group.name.asc()).all()
    form = {}

    if request.method == 'POST':
        form = {
            'username': form_str('username', 80),
            'email': form_str('email', 120).lower(),
            'full_name': form_str('full_name', 100),
            'group_id': form_int('group_id'),
        }
        password = request.form.get('password') or ''
        password2 = request.form.get('password2') or ''

        error = None
        if not all([form['username'], form['email'], password, form['full_name'], form['group_id']]):
            error = 'Заполните все поля: ИИН, ФИО, email, пароль и группу'
        elif not USERNAME_RE.match(form['username']):
            error = 'ИИН (логин) может содержать только цифры, латинские буквы, точку, дефис и подчёркивание'
        elif not EMAIL_RE.match(form['email']):
            error = 'Некорректный email'
        elif password != password2:
            error = 'Пароли не совпадают'
        elif security.password_problem(password):
            error = security.password_problem(password)
        elif User.query.filter_by(username=form['username']).first():
            error = 'Пользователь с таким ИИН уже зарегистрирован'
        elif User.query.filter_by(email=form['email']).first():
            error = 'Этот email уже используется'
        elif not db.session.get(Group, form['group_id']):
            error = 'Выбранная группа не найдена'
        elif not request.form.get('accept_privacy'):
            error = 'Нужно согласие на обработку персональных данных'

        if error:
            flash(error, 'danger')
        else:
            new_user = User(
                username=form['username'],
                email=form['email'],
                password=generate_password_hash(password),
                role='student',
                full_name=form['full_name'],
                group_id=form['group_id'],
                privacy_accepted_at=datetime.utcnow(),
            )
            db.session.add(new_user)
            db.session.commit()
            flash('Регистрация прошла успешно! Теперь вы можете войти.', 'success')
            return redirect(url_for('login'))

    return render_template('register.html', groups=all_groups, form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    username = ''
    if request.method == 'POST':
        username = form_str('username', 120)
        password = request.form.get('password') or ''
        ip = security.client_ip()

        if security.login_blocked(username, ip):
            flash('Слишком много неудачных попыток входа. Подождите 15 минут.', 'danger')
            return render_template('login.html', username=username), 429

        user = User.query.filter(
            or_(User.username == username, User.email == username.lower())
        ).first()

        if user and check_password_hash(user.password, password):
            security.clear_failed_logins(username, ip)
            login_user(user, remember=bool(request.form.get('remember')))
            if user.must_change_password:
                return redirect(url_for('change_password'))
            flash('Вы успешно вошли в систему!', 'success')
            target = request.form.get('next') or request.args.get('next')
            if security.is_safe_next(target):
                return redirect(target)
            return redirect(url_for('dashboard'))

        security.record_failed_login(username, ip)
        flash('Неверный логин или пароль', 'danger')

    return render_template('login.html', username=username)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Вы вышли из системы', 'info')
    return redirect(url_for('index'))


@app.route('/profile/password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current = request.form.get('current_password') or ''
        new = request.form.get('new_password') or ''
        new2 = request.form.get('new_password2') or ''

        error = None
        if not check_password_hash(current_user.password, current):
            error = 'Текущий пароль указан неверно'
        elif new != new2:
            error = 'Новые пароли не совпадают'
        elif security.password_problem(new):
            error = security.password_problem(new)
        elif new == current:
            error = 'Новый пароль должен отличаться от текущего'
        elif new.lower() == f'{current_user.username}abc'.lower() or new == current_user.username:
            error = 'Пароль не должен строиться из логина'

        if error:
            flash(error, 'danger')
        else:
            current_user.password = generate_password_hash(new)
            current_user.must_change_password = False
            db.session.commit()
            # остальные сессии этого пользователя теперь недействительны, текущую обновляем
            login_user(current_user._get_current_object())
            flash('Пароль изменён. На других устройствах нужно будет войти заново.', 'success')
            return redirect(url_for('dashboard'))

    return render_template('change_password.html', forced=current_user.must_change_password)


# ---------- DASHBOARD & PROFILE ----------


@app.route('/dashboard')
@login_required
def dashboard():
    user = current_user

    if user.role in ('admin', 'superadmin'):
        return redirect(url_for('admin.superadmin_home'))

    now = now_local()
    unread_messages = Message.query.filter_by(recipient_id=user.id, is_read=False).count()

    if user.role == 'psychologist':
        tests = (
            Test.query.filter_by(user_id=user.id)
            .order_by(Test.created_at.desc())
            .limit(5)
            .all()
        )
        pending_requests = (
            Appointment.query.filter_by(psychologist_id=user.id, status='pending')
            .order_by(Appointment.appointment_date.asc())
            .all()
        )
        upcoming = (
            Appointment.query.filter(
                Appointment.psychologist_id == user.id,
                Appointment.status == 'confirmed',
                Appointment.appointment_date >= now,
            )
            .order_by(Appointment.appointment_date.asc())
            .limit(5)
            .all()
        )
        alert_query = services.alert_results_query(user.id)
        alert_count = alert_query.count()
        alert_results = alert_query.order_by(TestResult.created_at.desc()).limit(8).all()
        recent_results = (
            TestResult.query.join(Test, Test.id == TestResult.test_id)
            .filter(Test.user_id == user.id)
            .order_by(TestResult.created_at.desc())
            .limit(8)
            .all()
        )
        return render_template(
            'psychologist_dashboard.html',
            user=user,
            tests=tests,
            unread_messages=unread_messages,
            students_count=User.query.filter_by(role='student').count(),
            pending_requests=pending_requests,
            upcoming=upcoming,
            alert_results=alert_results,
            alert_count=alert_count,
            recent_results=recent_results,
            has_alert_ranges=TestInterpretation.query.join(Test).filter(
                Test.user_id == user.id, TestInterpretation.is_alert.is_(True)
            ).count() > 0,
        )

    completed_ids = {r.test_id for r in TestResult.query.filter_by(user_id=user.id).all()}
    available_tests = [
        t for t in Test.query.filter_by(is_active=True).order_by(Test.created_at.desc()).all()
        if t.id not in completed_ids and t.questions
    ][:5]
    recent_results = (
        TestResult.query.filter_by(user_id=user.id)
        .order_by(TestResult.created_at.desc())
        .limit(5)
        .all()
    )
    upcoming_appointments = (
        Appointment.query.filter(
            Appointment.student_id == user.id,
            Appointment.status.in_(('pending', 'confirmed')),
            Appointment.appointment_date >= now,
        )
        .order_by(Appointment.appointment_date.asc())
        .all()
    )
    psychologists = User.query.filter_by(role='psychologist').order_by(User.full_name).all()
    return render_template(
        'student_dashboard.html',
        user=user,
        available_tests=available_tests,
        recent_results=recent_results,
        unread_messages=unread_messages,
        upcoming_appointments=upcoming_appointments,
        psychologists=psychologists,
    )


def can_view_profile(user: User) -> bool:
    # студенты видят психологов и себя; сотрудники — всех
    return current_user.id == user.id or user.is_staff or current_user.is_staff


@app.route('/profile/<username>')
@login_required
def profile(username):
    user = User.query.filter_by(username=username).first_or_404()
    if not can_view_profile(user):
        abort(403)
    can_edit = current_user.id == user.id
    posts_query = Post.query.filter_by(user_id=user.id)
    if not can_edit:
        posts_query = posts_query.filter(Post.is_anonymous.is_(False))
    posts = posts_query.order_by(Post.created_at.desc()).limit(10).all()
    return render_template('profile.html', user=user, posts=posts, can_edit=can_edit)


@app.route('/profile/edit', methods=['GET', 'POST'])
@login_required
def edit_profile():
    user = current_user
    if request.method == 'POST':
        full_name = form_str('full_name', 100)
        if not full_name:
            flash('Укажите имя', 'danger')
            return redirect(url_for('edit_profile'))
        user.full_name = full_name
        user.bio = form_str('bio', 2000) or None

        folder = app.config['UPLOAD_FOLDER']
        file = request.files.get('profile_pic')
        if file and file.filename:
            try:
                filename = security.save_image(file, folder)
            except ValueError as e:
                flash(str(e), 'danger')
                return redirect(url_for('edit_profile'))
            security.remove_upload(folder, user.profile_pic)
            user.profile_pic = filename
        elif request.form.get('remove_pic'):
            security.remove_upload(folder, user.profile_pic)
            user.profile_pic = None

        db.session.commit()
        flash('Профиль успешно обновлён', 'success')
        return redirect(url_for('profile', username=user.username))
    return render_template('edit_profile.html', user=user)


@app.route('/psychologists')
def psychologists():
    items = User.query.filter_by(role='psychologist').order_by(User.full_name).all()
    return render_template('psychologists.html', psychologists=items)


# ---------- TESTS ----------


def _result_counts(test_ids):
    if not test_ids:
        return {}
    rows = (
        db.session.query(TestResult.test_id, func.count(TestResult.id))
        .filter(TestResult.test_id.in_(test_ids))
        .group_by(TestResult.test_id)
        .all()
    )
    return dict(rows)


@app.route('/tests')
@login_required
def tests():
    user = current_user
    if user.role == 'psychologist':
        my_tests = (
            Test.query.filter_by(user_id=user.id)
            .order_by(Test.created_at.desc())
            .all()
        )
        counts = _result_counts([t.id for t in my_tests])
        return render_template(
            'psychologist_tests.html',
            tests=my_tests,
            result_counts=counts,
            total_students=User.query.filter_by(role='student').count(),
            total_results=sum(counts.values()),
        )

    available_tests = [
        t for t in Test.query.filter_by(is_active=True).order_by(Test.created_at.desc()).all()
        if t.questions
    ]
    completed = {}
    for r in TestResult.query.filter_by(user_id=user.id).order_by(TestResult.created_at.asc()).all():
        completed[r.test_id] = r
    return render_template(
        'student_tests.html',
        tests=available_tests,
        completed=completed,
    )


@app.route('/tests/create', methods=['GET', 'POST'])
@roles_required('psychologist')
def create_test():
    if request.method == 'POST':
        title_ru = form_str('title', 200)
        title_kk = form_str('title_kk', 200)
        description_ru = form_str('description')
        description_kk = form_str('description_kk')
        test_type = request.form.get('test_type', 'classic')
        if test_type not in TEST_TYPES:
            test_type = 'classic'

        if not title_ru and not title_kk:
            flash('Нужно указать хотя бы одно название теста (RU или KZ)', 'danger')
            return redirect(url_for('create_test'))

        test = Test(
            user_id=current_user.id,
            title=title_ru or title_kk,
            title_kk=title_kk or None,
            description=description_ru or None,
            description_kk=description_kk or None,
            test_type=test_type,
            # тест без вопросов студентам не показываем; активируется при сохранении
            is_active=True,
        )
        db.session.add(test)
        db.session.flush()  # нужен test.id

        if test_type == 'scale':
            for i, (ru, kk, score) in enumerate(DEFAULT_SCALE):
                db.session.add(
                    TestScaleOption(
                        test_id=test.id, order_index=i, label_ru=ru, label_kk=kk, score=score,
                    )
                )

        db.session.commit()
        flash('Тест создан. Теперь добавьте вопросы.', 'success')
        return redirect(url_for('add_questions', test_id=test.id))

    return render_template('create_test.html', test_types=TEST_TYPES)


def _read_option_rows():
    """Строки вариантов из формы конструктора: [(ru, kk, score), ...]."""
    rows = []
    texts_ru = request.form.getlist('option_text_ru[]')
    texts_kk = request.form.getlist('option_text_kk[]')
    scores = request.form.getlist('option_score[]')
    for ru, kk, score in zip(texts_ru, texts_kk, scores):
        ru = (ru or '').strip()[:200]
        kk = (kk or '').strip()[:200]
        if not ru and not kk:
            continue
        try:
            score_val = int(score)
        except (TypeError, ValueError):
            score_val = 0
        rows.append((ru or kk, kk or None, score_val))
    return rows


@app.route('/tests/<int:test_id>/questions', methods=['GET', 'POST'])
@roles_required('psychologist')
def add_questions(test_id):
    test = own_test_or_403(test_id)

    # Удаление вопроса
    if request.method == 'POST' and 'delete_question' in request.form:
        q = db.session.get(Question, form_int('delete_question'))
        if q is None or q.test_id != test.id:
            abort(404)
        answers = TestAnswer.query.filter_by(question_id=q.id).count()
        if answers:
            flash(f'На этот вопрос уже ответили ({answers}). Удаление стёрло бы ответы и исказило '
                  'сохранённые баллы. Исправьте текст вопроса или создайте новую версию теста.', 'warning')
            return redirect(url_for('add_questions', test_id=test.id))
        position = [x.id for x in test.questions].index(q.id) + 1
        db.session.delete(q)
        services.renumber_subscales_after_delete(test, position)
        db.session.commit()
        flash('Вопрос удалён', 'success')
        return redirect(url_for('add_questions', test_id=test.id))

    # Добавление нового вопроса
    if request.method == 'POST':
        text_ru = form_str('text_ru')
        text_kk = form_str('text_kk')

        if not text_ru and not text_kk:
            flash('Введите текст вопроса хотя бы на одном языке', 'danger')
            return redirect(url_for('add_questions', test_id=test.id))

        if test.test_type == 'scale':
            question_type = 'scale_choice'
            scale_opts = list(test.scale_options)
            if not scale_opts:
                flash('Сначала задайте шкальные варианты для теста', 'danger')
                return redirect(url_for('add_questions', test_id=test.id))
        else:
            question_type = request.form.get('question_type')
            if question_type not in QUESTION_TYPES:
                flash('Выберите тип вопроса', 'danger')
                return redirect(url_for('add_questions', test_id=test.id))
            option_rows = _read_option_rows() if question_type != 'text' else []
            if question_type != 'text' and len(option_rows) < 2:
                flash('Для вопроса с вариантами нужно минимум два варианта ответа', 'danger')
                return redirect(url_for('add_questions', test_id=test.id))

        question = Question(
            test_id=test.id,
            text=text_ru or text_kk,
            text_kk=text_kk or None,
            question_type=question_type,
        )
        db.session.add(question)
        db.session.flush()

        if test.test_type == 'scale':
            for so in scale_opts:
                db.session.add(QuestionOption(
                    question_id=question.id, text=so.label_ru, text_kk=so.label_kk, score=so.score,
                ))
        else:
            for ru, kk, score in option_rows:
                db.session.add(QuestionOption(question_id=question.id, text=ru, text_kk=kk, score=score))

        db.session.commit()
        flash('Вопрос добавлен', 'success')
        return redirect(url_for('add_questions', test_id=test.id) + '#new-question')

    return render_template(
        'add_questions.html',
        test=test,
        max_score=services.test_max_score(test),
        interpretation_issues=services.interpretation_issues(test),
        result_count=TestResult.query.filter_by(test_id=test.id).count(),
    )


@app.route('/tests/<int:test_id>/questions/<int:question_id>/edit', methods=['GET', 'POST'])
@roles_required('psychologist')
def edit_question(test_id, question_id):
    test = own_test_or_403(test_id)
    question = get_or_404(Question, question_id)
    if question.test_id != test.id:
        abort(404)

    if request.method == 'POST':
        text_ru = form_str('text_ru')
        text_kk = form_str('text_kk')
        if not text_ru and not text_kk:
            flash('Введите текст вопроса хотя бы на одном языке', 'danger')
            return redirect(url_for('edit_question', test_id=test.id, question_id=question.id))
        question.text = text_ru or text_kk
        question.text_kk = text_kk or None

        # В шкаловом тесте подписи берутся из шкалы, но баллы можно задать свои (обратный ключ)
        if test.test_type == 'scale':
            for opt in question.options:
                score = form_int(f'option_score_{opt.id}')
                if score is not None:
                    opt.score = score
        elif question.question_type != 'text':
            kept = 0
            for opt in list(question.options):
                if request.form.get(f'delete_option_{opt.id}'):
                    used = TestAnswer.query.filter_by(option_id=opt.id).count()
                    if used:
                        flash(f'Вариант «{opt.text}» уже выбирали студенты ({used}), он оставлен', 'warning')
                        kept += 1
                        continue
                    db.session.delete(opt)
                    continue
                ru = form_str(f'option_ru_{opt.id}', 200)
                kk = form_str(f'option_kk_{opt.id}', 200)
                if ru or kk:
                    opt.text = ru or kk
                    opt.text_kk = kk or None
                score = form_int(f'option_score_{opt.id}')
                if score is not None:
                    opt.score = score
                kept += 1
            for ru, kk, score in _read_option_rows():
                db.session.add(QuestionOption(question_id=question.id, text=ru, text_kk=kk, score=score))
                kept += 1
            if kept < 2:
                db.session.rollback()
                flash('У вопроса должно остаться минимум два варианта ответа', 'danger')
                return redirect(url_for('edit_question', test_id=test.id, question_id=question.id))

        db.session.commit()
        flash('Вопрос сохранён', 'success')
        return redirect(url_for('add_questions', test_id=test.id))

    number = [q.id for q in test.questions].index(question.id) + 1
    return render_template('edit_question.html', test=test, question=question, number=number)


@app.route('/tests/<int:test_id>/scale-options', methods=['POST'])
@roles_required('psychologist')
def update_scale_options(test_id):
    test = own_test_or_403(test_id)
    if test.test_type != 'scale':
        abort(400)

    rows = []
    for ru, kk, score in zip(
        request.form.getlist('scale_label_ru[]'),
        request.form.getlist('scale_label_kk[]'),
        request.form.getlist('scale_score[]'),
    ):
        ru = (ru or '').strip()[:200]
        kk = (kk or '').strip()[:200]
        if not ru and not kk:
            continue
        try:
            score_val = int(score)
        except (TypeError, ValueError):
            score_val = 0
        rows.append((ru or kk, kk or None, score_val))

    if len(rows) < 2:
        flash('В шкале должно быть минимум два варианта ответа', 'danger')
        return redirect(url_for('add_questions', test_id=test.id))

    old_scale = [(so.label_ru, so.score) for so in test.scale_options]
    has_results = TestResult.query.filter_by(test_id=test.id).first() is not None
    if has_results and len(rows) != len(old_scale):
        flash('Тест уже проходили: можно менять подписи и баллы вариантов, но не их количество. '
              'Иначе старые ответы получат чужие подписи. Для новой шкалы создайте новый тест.', 'danger')
        return redirect(url_for('add_questions', test_id=test.id))

    TestScaleOption.query.filter_by(test_id=test.id).delete()
    for i, (ru, kk, score) in enumerate(rows):
        db.session.add(TestScaleOption(test_id=test.id, order_index=i, label_ru=ru, label_kk=kk, score=score))

    # Применяем шкалу только к вопросам, у которых варианты в точности совпадают
    # со старой шкалой. Вопросы с обратным ключом (другие баллы) и вручную
    # изменённые вопросы не трогаем.
    synced = skipped = 0
    for question in test.questions:
        options = list(question.options)
        if [(o.text, o.score) for o in options] != old_scale:
            skipped += 1
            continue
        for i, (ru, kk, score) in enumerate(rows):
            if i < len(options):
                options[i].text, options[i].text_kk, options[i].score = ru, kk, score
            else:
                db.session.add(QuestionOption(question_id=question.id, text=ru, text_kk=kk, score=score))
        for extra in options[len(rows):]:
            db.session.delete(extra)  # без результатов на них никто не ссылается
        synced += 1

    db.session.commit()
    flash(f'Шкала сохранена и применена к {synced} вопросам', 'success')
    if skipped:
        flash(f'{skipped} вопросов с собственными баллами (например, с обратным ключом) не изменены — '
              'их варианты правятся в редактировании вопроса', 'info')
    return redirect(url_for('add_questions', test_id=test.id))


@app.route('/tests/<int:test_id>/edit', methods=['GET', 'POST'])
@roles_required('psychologist')
def edit_test(test_id):
    test = own_test_or_403(test_id)

    if request.method == 'POST':
        title_ru = form_str('title', 200)
        title_kk = form_str('title_kk', 200)
        if not title_ru and not title_kk:
            flash('Нужно указать хотя бы одно название теста', 'danger')
            return redirect(url_for('edit_test', test_id=test.id))
        test.title = title_ru or title_kk
        test.title_kk = title_kk or None
        test.description = form_str('description') or None
        test.description_kk = form_str('description_kk') or None
        test.is_active = 'is_active' in request.form
        if test.is_active and not test.questions:
            flash('В тесте нет вопросов — студенты увидят его, когда вы их добавите', 'warning')
        db.session.commit()
        flash('Тест обновлён', 'success')
        return redirect(url_for('tests'))
    return render_template('edit_test.html', test=test)


@app.route('/tests/<int:test_id>/delete', methods=['POST'])
@roles_required('psychologist')
def delete_test(test_id):
    test = own_test_or_403(test_id)
    result_count = TestResult.query.filter_by(test_id=test.id).count()
    if result_count and form_int('confirm_results') != result_count:
        flash(
            f'У теста {result_count} результатов студентов. Удаление сотрёт их без возможности '
            'восстановления. Если тест больше не нужен, лучше снимите отметку «Тест активен».',
            'warning',
        )
        return redirect(url_for('tests'))

    db.session.delete(test)
    db.session.commit()
    flash('Тест удалён', 'success')
    return redirect(url_for('tests'))


def _results_rows(test: Test):
    return (
        TestResult.query.filter_by(test_id=test.id)
        .join(User, User.id == TestResult.user_id)
        .outerjoin(Group, Group.id == User.group_id)
        .options(joinedload(TestResult.user))
        .order_by(Group.name.asc(), User.full_name.asc(), TestResult.created_at.asc())
        .all()
    )


@app.route('/tests/<int:test_id>/results')
@roles_required('psychologist')
def test_results(test_id):
    test = own_test_or_403(test_id)
    results = _results_rows(test)
    alert_ranges = [(i.min_score, i.max_score) for i in test.interpretations if i.is_alert]
    alerts = {
        r.id for r in results
        if r.score is not None and any(lo <= r.score <= hi for lo, hi in alert_ranges)
    }
    groups = sorted({r.user.group.name for r in results if r.user.group})
    return render_template(
        'test_results.html',
        test=test,
        results=results,
        alerts=alerts,
        groups=groups,
        max_score=services.test_max_score(test),
    )


@app.route('/tests/<int:test_id>/download_results')
@roles_required('psychologist')
def download_test_results(test_id):
    test = own_test_or_403(test_id)

    grouped: dict[str, list] = {}
    for r in _results_rows(test):
        gname = r.user.group.name if r.user.group else 'Без группы'
        grouped.setdefault(gname, []).append((
            r.user.full_name or '—',
            r.user.username,
            _fmt_ts(r.created_at, '%d.%m.%Y'),
            '' if r.score is None else r.score,
            r.result_text or '—',
        ))
    pdf = pdf_utils.test_results_pdf(test.title, sorted(grouped.items()))
    return send_file(pdf, as_attachment=True, download_name=f'test_results_{test.id}.pdf',
                     mimetype='application/pdf')


@app.route('/tests/<int:test_id>/export.csv')
@roles_required('psychologist')
def export_test_results(test_id):
    test = own_test_or_403(test_id)
    questions = list(test.questions)
    results = _results_rows(test)

    out = io.StringIO()
    writer = csv.writer(out, delimiter=';')
    header = ['ФИО', 'Логин', 'Группа', 'Курс', 'Дата', 'Язык', 'Балл', 'Интерпретация']
    header += [f'Подшкала: {s.name}' for s in test.subscales]
    header += [f'В{i}' for i in range(1, len(questions) + 1)]
    writer.writerow(header)

    for r in results:
        answers: dict[int, list] = {}
        for a in r.answers:
            if a.option is not None:
                answers.setdefault(a.question_id, []).append(f'{a.option.text} ({a.option.score or 0})')
            elif a.answer_text:
                answers.setdefault(a.question_id, []).append(a.answer_text)
        profile = {p['name']: p['score'] for p in services.subscale_profile(test, services.per_question_scores(r))}
        row = [
            r.user.full_name, r.user.username,
            r.user.group.name if r.user.group else '', r.user.group.course if r.user.group else '',
            _fmt_ts(r.created_at), r.language or 'ru', r.score, r.result_text,
        ]
        row += [profile.get(s.name, '') for s in test.subscales]
        row += [' | '.join(answers.get(q.id, [])) for q in questions]
        writer.writerow([services.csv_safe(c) for c in row])

    data = '﻿' + out.getvalue()  # BOM — чтобы Excel открыл кириллицу
    return Response(
        data,
        mimetype='text/csv; charset=utf-8',
        headers={'Content-Disposition': f'attachment; filename=test_{test.id}_results.csv'},
    )


@app.route('/tests/<int:test_id>/recalculate', methods=['POST'])
@roles_required('psychologist')
def recalculate_results(test_id):
    """Пересчитать баллы и интерпретации по сохранённым ответам (после правки шкалы/диапазонов)."""
    test = own_test_or_403(test_id)
    changed = 0
    for r in TestResult.query.filter_by(test_id=test.id).all():
        score = sum(services.per_question_scores(r).values())
        text = services.interpretation_text(test, score)
        if r.score != score or r.result_text != text:
            r.score, r.result_text = score, text
            changed += 1
    db.session.commit()
    flash(f'Пересчитано результатов: {changed}', 'success')
    return redirect(url_for('add_questions', test_id=test.id))


@app.route('/tests/<int:test_id>/add_interpretation', methods=['POST'])
@roles_required('psychologist')
def add_interpretation(test_id):
    test = own_test_or_403(test_id)
    back = redirect(url_for('add_questions', test_id=test.id) + '#interpretations')

    for action in ('delete_interpretation', 'toggle_alert'):
        if action in request.form:
            interp = db.session.get(TestInterpretation, form_int(action))
            if interp is None or interp.test_id != test.id:
                abort(404)
            if action == 'delete_interpretation':
                db.session.delete(interp)
                flash('Интерпретация удалена', 'info')
            else:
                interp.is_alert = not interp.is_alert
            db.session.commit()
            return back

    min_score = form_int('min_score')
    max_score = form_int('max_score')
    text = form_str('text')
    if min_score is None or max_score is None or not text:
        flash('Укажите диапазон баллов и текст интерпретации', 'danger')
        return back
    if min_score > max_score:
        flash('Значение «от» не может быть больше «до»', 'danger')
        return back

    db.session.add(TestInterpretation(
        test_id=test.id,
        min_score=min_score,
        max_score=max_score,
        text=text,
        is_alert=bool(request.form.get('is_alert')),
    ))
    db.session.commit()
    flash('Интерпретация добавлена', 'success')
    return back


@app.route('/tests/<int:test_id>/subscales', methods=['POST'])
@roles_required('psychologist')
def manage_subscales(test_id):
    test = own_test_or_403(test_id)
    back = redirect(url_for('add_questions', test_id=test.id) + '#subscales')

    if 'delete_subscale' in request.form:
        sub = db.session.get(TestSubscale, form_int('delete_subscale'))
        if sub is None or sub.test_id != test.id:
            abort(404)
        db.session.delete(sub)
        db.session.commit()
        flash('Подшкала удалена', 'info')
        return back

    name = form_str('name', 200)
    raw = form_str('question_numbers', 500)
    if not name:
        flash('Укажите название подшкалы', 'danger')
        return back
    try:
        numbers = services.parse_question_numbers(raw)
    except ValueError as e:
        flash(str(e), 'danger')
        return back
    total = len(test.questions)
    missing = sorted(n for n in numbers if n > total)
    if missing:
        flash(f'В тесте {total} вопросов, номера {", ".join(map(str, missing))} пока не существуют', 'warning')
    db.session.add(TestSubscale(test_id=test.id, name=name, question_numbers=raw))
    db.session.commit()
    flash('Подшкала добавлена', 'success')
    return back


@app.route('/tests/<int:test_id>/take', methods=['GET', 'POST'])
@login_required
def take_test(test_id):
    test = get_or_404(Test, test_id)
    is_owner = is_psychologist() and test.user_id == current_user.id
    if not test.is_active and not is_owner:
        flash('Этот тест сейчас недоступен', 'info')
        return redirect(url_for('tests'))

    has_kk = services.test_has_kazakh(test)
    lang = request.args.get('lang') or request.form.get('lang')
    if request.method == 'GET' and not lang and has_kk:
        return render_template('choose_test_lang.html', test=test)
    if lang not in ('ru', 'kk') or (lang == 'kk' and not has_kk):
        lang = 'ru'

    preview = not is_student()
    errors: set[int] = set()

    if request.method == 'POST':
        if preview:
            flash('Это режим предпросмотра: проходить тесты могут только студенты', 'info')
            return redirect(url_for('take_test', test_id=test.id, lang=lang))

        chosen: dict[int, list] = {}
        texts: dict[int, str] = {}
        for question in test.questions:
            field = f'answer_{question.id}'
            if question.question_type == 'text':
                texts[question.id] = (request.form.get(field) or '').strip()[:5000]
                continue
            valid = {opt.id: opt for opt in question.options}
            if not valid:
                continue
            raw_values = (
                request.form.getlist(field)
                if question.question_type == 'multiple_choice'
                else [request.form.get(field)]
            )
            picked = []
            for raw in raw_values:
                try:
                    option = valid.get(int(raw))
                except (TypeError, ValueError):
                    option = None
                if option is not None and option not in picked:
                    picked.append(option)
            if not picked:
                errors.add(question.id)
            else:
                chosen[question.id] = picked

        if errors:
            flash(f'Ответьте, пожалуйста, на все вопросы (пропущено: {len(errors)})', 'warning')
        else:
            test_result = TestResult(
                user_id=current_user.id,
                test_id=test.id,
                created_at=datetime.utcnow(),
                language=lang,
            )
            db.session.add(test_result)
            db.session.flush()

            total_score = 0
            for question in test.questions:
                if question.question_type == 'text':
                    db.session.add(TestAnswer(
                        test_result_id=test_result.id, question_id=question.id,
                        answer_text=texts.get(question.id) or None,
                    ))
                    continue
                for option in chosen.get(question.id, []):
                    total_score += option.score or 0
                    db.session.add(TestAnswer(
                        test_result_id=test_result.id, question_id=question.id, option_id=option.id,
                    ))

            test_result.score = total_score
            test_result.result_text = services.interpretation_text(test, total_score)
            db.session.commit()
            return redirect(url_for('test_result', result_id=test_result.id))

    return render_template(
        'take_test.html',
        test=test,
        lang=lang,
        has_kk=has_kk,
        preview=preview,
        errors=errors,
        previous=request.form if request.method == 'POST' else None,
    )


@app.route('/test_result/<int:result_id>')
@login_required
def test_result(result_id):
    result = get_or_404(TestResult, result_id)

    if is_student() and result.user_id != current_user.id:
        abort(403)
    if is_psychologist() and result.test.user_id != current_user.id:
        abort(403)

    test = result.test
    by_question: dict[int, list] = {}
    for answer in result.answers:
        by_question.setdefault(answer.question_id, []).append(answer)
    rows = []
    for number, question in enumerate(test.questions, start=1):
        answers = by_question.get(question.id, [])
        rows.append({
            'number': number,
            'question': question,
            'options': [a.option for a in answers if a.option is not None],
            'text': next((a.answer_text for a in answers if a.answer_text), None),
            'score': sum((a.option.score or 0) for a in answers if a.option is not None),
        })

    return render_template(
        'test_result.html',
        result=result,
        rows=rows,
        max_score=services.test_max_score(test),
        profile=services.subscale_profile(test, services.per_question_scores(result)),
        is_alert=services.result_is_alert(result),
    )


# ---------- ANALYTICS & REPORTS ----------


def get_student_or_404(student_id: int) -> User:
    student = get_or_404(User, student_id)
    if student.role != 'student':
        abort(404)
    return student


@app.route('/analytics/students')
@roles_required('psychologist')
def student_list():
    students = (
        User.query.filter_by(role='student')
        .options(joinedload(User.group))
        .order_by(User.created_at.desc())
        .all()
    )
    return render_template('student_list.html', students=students)


@app.route('/analytics/students/<int:student_id>')
@roles_required('psychologist')
def student_analytics(student_id):
    student = get_student_or_404(student_id)

    test_results = (
        TestResult.query.filter_by(user_id=student_id)
        .options(joinedload(TestResult.test))
        .order_by(TestResult.created_at.asc())
        .all()
    )
    # график: по линии на каждый тест — баллы разных методик несопоставимы
    series: dict[str, list] = {}
    for r in test_results:
        series.setdefault(r.test.title, []).append({'x': _fmt_ts(r.created_at, '%Y-%m-%d'), 'y': r.score or 0})

    appointments = (
        Appointment.query.filter_by(student_id=student.id, psychologist_id=current_user.id)
        .order_by(Appointment.appointment_date.desc())
        .all()
    )

    return render_template(
        'student_analytics.html',
        student=student,
        test_results=list(reversed(test_results)),
        own_test_ids={t.id for t in Test.query.filter_by(user_id=current_user.id).all()},
        alerts={r.id for r in test_results if services.result_is_alert(r)},
        series=series,
        messages_sent=Message.query.filter(
            Message.sender_id == student_id, Message.is_anonymous.isnot(True)
        ).count(),
        posts_count=Post.query.filter_by(user_id=student_id, is_anonymous=False).count(),
        reports=StudentReport.query.filter_by(student_id=student_id, psychologist_id=current_user.id)
        .order_by(StudentReport.created_at.desc()).all(),
        protocols=MeetingProtocol.query.filter_by(student_id=student_id, psychologist_id=current_user.id)
        .order_by(MeetingProtocol.session_date.desc()).all(),
        appointments=appointments,
    )


REPORT_FIELDS = [
    ('academic_performance', 'Учебная успеваемость'),
    ('emotional_state', 'Эмоциональное состояние'),
    ('social_interaction', 'Социальное взаимодействие'),
    ('stress_level', 'Уровень стресса'),
    ('sleep_quality', 'Качество сна'),
    ('motivation', 'Мотивация'),
    ('behavior_patterns', 'Поведенческие паттерны'),
    ('recommendations', 'Рекомендации'),
    ('additional_notes', 'Дополнительные заметки'),
]


@app.route('/analytics/students/<int:student_id>/report', methods=['GET', 'POST'])
@roles_required('psychologist')
def create_report(student_id):
    student = get_student_or_404(student_id)

    if request.method == 'POST':
        values = {name: form_str(name) or None for name, _ in REPORT_FIELDS}
        if not any(values.values()):
            flash('Заполните хотя бы одно поле отчёта', 'danger')
            return render_template('create_report.html', student=student, fields=REPORT_FIELDS, values=values)
        report = StudentReport(
            student_id=student.id,
            psychologist_id=current_user.id,
            created_at=datetime.utcnow(),
            **values,
        )
        db.session.add(report)
        db.session.commit()
        flash('Отчёт создан', 'success')
        return redirect(url_for('student_analytics', student_id=student.id))
    return render_template('create_report.html', student=student, fields=REPORT_FIELDS, values={})


@app.route('/analytics/students/<int:student_id>/report/<int:report_id>/download')
@roles_required('psychologist')
def download_report(student_id, report_id):
    report = get_or_404(StudentReport, report_id)
    if report.student_id != student_id or report.psychologist_id != current_user.id:
        abort(403)
    student = db.session.get(User, report.student_id)
    pdf = pdf_utils.student_report_pdf(report, student, current_user, utc_to_local(report.created_at))
    created = report.created_at.strftime('%Y%m%d') if report.created_at else 'report'
    return send_file(pdf, as_attachment=True, mimetype='application/pdf',
                     download_name=f'report_{student_id}_{created}.pdf')


# ---------- APPOINTMENTS & MEETINGS ----------


def _notify(sender_id: int, recipient_id: int, text: str) -> None:
    db.session.add(Message(content=text, sender_id=sender_id, recipient_id=recipient_id, is_anonymous=False))


@app.route('/appointments')
@login_required
def appointments():
    user = current_user
    if user.role not in ('student', 'psychologist'):
        return redirect(url_for('dashboard'))

    owner_field = Appointment.psychologist_id if user.role == 'psychologist' else Appointment.student_id
    items = (
        Appointment.query.filter(owner_field == user.id)
        .order_by(Appointment.appointment_date.asc())
        .all()
    )
    now = now_local()
    sections = {
        'pending': [a for a in items if a.status == 'pending' and a.appointment_date >= now],
        'upcoming': [a for a in items if a.status == 'confirmed' and a.appointment_date >= now],
        'past': sorted(
            [a for a in items if a.status == 'completed'
             or (a.status in ('confirmed', 'pending') and a.appointment_date < now)],
            key=lambda a: a.appointment_date, reverse=True,
        ),
        'cancelled': sorted(
            [a for a in items if a.status == 'cancelled'],
            key=lambda a: a.appointment_date, reverse=True,
        ),
    }

    meetings = {}
    protocols = []
    if user.role == 'psychologist':
        for a in items:
            meeting = services.find_meeting(a)
            if meeting is not None:
                meetings[a.id] = meeting
        protocols = (
            MeetingProtocol.query.filter_by(psychologist_id=user.id)
            .order_by(MeetingProtocol.session_date.desc())
            .all()
        )

    return render_template(
        'appointments.html',
        sections=sections,
        meetings=meetings,
        protocols=protocols,
        now=now,
    )


@app.route('/appointments/create/<int:student_id>', methods=['GET', 'POST'])
@roles_required('psychologist')
def create_appointment(student_id):
    student = get_student_or_404(student_id)

    if request.method == 'POST':
        when = services.parse_local_datetime(request.form.get('appointment_date'))
        purpose = form_str('purpose', 1000)
        if when is None:
            flash('Укажите дату и время встречи', 'danger')
        else:
            appointment, error = services.schedule_appointment(student, current_user, when, purpose, current_user)
            if error:
                flash(error, 'danger')
            else:
                _notify(current_user.id, student.id,
                        f"Назначена встреча на {when.strftime('%d.%m.%Y %H:%M')}. "
                        f"Цель: {purpose or 'не указана'}")
                db.session.commit()
                flash('Встреча назначена, студент получил уведомление', 'success')
                return redirect(url_for('appointments'))
    return render_template('create_appointment.html', student=student)


APPOINTMENT_ACTIONS = {
    # действие: (новый статус, из каких статусов, кто может)
    'confirm': ('confirmed', ('pending',), ('psychologist',)),
    'cancel': ('cancelled', ('pending', 'confirmed'), ('psychologist', 'student')),
    'complete': ('completed', ('confirmed', 'pending'), ('psychologist',)),
}


@app.route('/appointments/<int:appointment_id>/update', methods=['POST'])
@login_required
def update_appointment(appointment_id):
    appointment = get_or_404(Appointment, appointment_id)
    user = current_user
    if user.id not in (appointment.student_id, appointment.psychologist_id):
        abort(403)

    action = request.form.get('action')
    if action not in APPOINTMENT_ACTIONS:
        abort(400)
    new_status, allowed_from, allowed_roles = APPOINTMENT_ACTIONS[action]
    if user.role not in allowed_roles:
        abort(403)
    if appointment.status not in allowed_from:
        flash('Статус встречи уже изменился, обновите страницу', 'warning')
        return redirect(url_for('appointments'))
    is_future = appointment.appointment_date > now_local()
    if action == 'confirm' and not is_future:
        flash('Время встречи уже прошло — отметьте, состоялась ли она', 'warning')
        return redirect(url_for('appointments'))
    if action == 'complete' and is_future:
        flash('Встреча ещё не началась', 'warning')
        return redirect(url_for('appointments'))
    if action == 'cancel' and user.role == 'student' and not is_future:
        flash('Встреча уже прошла, отменить её нельзя', 'warning')
        return redirect(url_for('appointments'))

    appointment.status = new_status
    services.meeting_for(appointment)

    recipient_id = appointment.student_id if user.id == appointment.psychologist_id else appointment.psychologist_id
    when = appointment.appointment_date.strftime('%d.%m.%Y %H:%M')
    reason = form_str('reason', 500)
    text = f'Встреча {when}: {APPOINTMENT_STATUSES[new_status].lower()}.'
    if reason:
        text += f' Комментарий: {reason}'
    _notify(user.id, recipient_id, text)
    db.session.commit()

    flash(f'Встреча {when}: {APPOINTMENT_STATUSES[new_status].lower()}', 'success')
    return redirect(request.form.get('next') if security.is_safe_next(request.form.get('next'))
                    else url_for('appointments'))


@app.route('/meetings/<int:meeting_id>/create_protocol', methods=['GET', 'POST'])
@roles_required('psychologist')
def create_protocol(meeting_id):
    meeting = get_or_404(Meeting, meeting_id)
    if meeting.psychologist_id != current_user.id:
        abort(403)
    if meeting.status == 'cancelled':
        flash('Встреча отменена, протокол к ней создать нельзя', 'warning')
        return redirect(url_for('appointments'))
    if meeting.scheduled_at > now_local():
        flash('Протокол заполняется после встречи', 'warning')
        return redirect(url_for('appointments'))

    if request.method == 'POST':
        duration = form_int('duration')
        if duration is None or not 1 <= duration <= 600:
            flash('Укажите продолжительность в минутах (от 1 до 600)', 'danger')
            return render_template('create_protocol.html', meeting=meeting, values=request.form)
        protocol = MeetingProtocol(
            meeting_id=meeting.id,
            student_id=meeting.student_id,
            psychologist_id=current_user.id,
            session_date=meeting.scheduled_at,
            duration=duration,
            topics_discussed=form_str('topics_discussed') or None,
            emotional_state=form_str('emotional_state') or None,
            progress_notes=form_str('progress_notes') or None,
            recommendations=form_str('recommendations') or None,
            homework=form_str('homework') or None,
            additional_comments=form_str('additional_comments') or None,
            created_at=datetime.utcnow(),
        )
        db.session.add(protocol)

        # протокол означает, что встреча состоялась
        meeting.status = 'completed'
        appointment = services.appointment_for(meeting)
        if appointment is not None and appointment.status != 'cancelled':
            appointment.status = 'completed'
        db.session.commit()

        flash('Протокол встречи сохранён', 'success')
        return redirect(url_for('appointments'))
    return render_template('create_protocol.html', meeting=meeting, values={})


@app.route('/appointments/<int:appointment_id>/protocol')
@roles_required('psychologist')
def appointment_protocol(appointment_id):
    """Открыть протокол встречи: создаёт запись встречи для старых данных при необходимости."""
    appointment = get_or_404(Appointment, appointment_id)
    if appointment.psychologist_id != current_user.id:
        abort(403)
    meeting = services.meeting_for(appointment)
    db.session.commit()
    return redirect(url_for('create_protocol', meeting_id=meeting.id))


@app.route('/protocols/<int:protocol_id>/download')
@roles_required('psychologist')
def download_protocol(protocol_id):
    protocol = get_or_404(MeetingProtocol, protocol_id)
    if protocol.psychologist_id != current_user.id:
        abort(403)
    student = db.session.get(User, protocol.student_id)
    pdf = pdf_utils.protocol_pdf(protocol, student, current_user)
    return send_file(
        pdf, as_attachment=True, mimetype='application/pdf',
        download_name=f"protocol_{protocol.student_id}_{protocol.session_date.strftime('%Y%m%d')}.pdf",
    )


@app.route('/api/meetings/calendar')
@login_required
def meetings_calendar():
    if not is_psychologist():
        return jsonify({'error': 'Forbidden'}), 403

    colors = {'pending': '#eab308', 'confirmed': '#4f46e5', 'completed': '#22c55e'}
    items = Appointment.query.filter(
        Appointment.psychologist_id == current_user.id,
        Appointment.status != 'cancelled',
    ).all()
    events = [
        {
            'id': a.id,
            'title': a.student.display_name,
            'start': a.appointment_date.isoformat(),
            'color': colors.get(a.status, '#64748b'),
            'extendedProps': {
                'status': APPOINTMENT_STATUSES.get(a.status, a.status),
                'purpose': a.purpose or '',
            },
        }
        for a in items
    ]
    return jsonify(events)


# ---------- POSTS & COMMENTS ----------


def can_moderate() -> bool:
    return current_user.is_authenticated and current_user.is_staff


@app.route('/posts')
@login_required
def posts():
    page = request.args.get('page', 1, type=int)
    pagination = Post.query.order_by(Post.created_at.desc()).paginate(
        page=page, per_page=20, error_out=False
    )
    psychologists = (
        User.query.filter_by(role='psychologist')
        .order_by(func.random())
        .limit(5)
        .all()
    )
    return render_template('posts.html', posts=pagination.items, pagination=pagination,
                           psychologists=psychologists, can_moderate=can_moderate())


def _post_form_values():
    return form_str('title', 200), form_str('content', 20000)


@app.route('/posts/create', methods=['GET', 'POST'])
@login_required
def create_post():
    if request.method == 'POST':
        title, content = _post_form_values()
        if not title or not content:
            flash('Заполните заголовок и текст', 'danger')
            return render_template('create_post.html', post=None, values=request.form)
        post = Post(
            title=title,
            content=content,
            user_id=current_user.id,
            is_anonymous=is_student() and bool(request.form.get('is_anonymous')),
        )
        db.session.add(post)
        db.session.commit()
        flash('Пост опубликован', 'success')
        return redirect(url_for('view_post', post_id=post.id))
    return render_template('create_post.html', post=None, values={})


@app.route('/posts/<int:post_id>')
@login_required
def view_post(post_id):
    post = get_or_404(Post, post_id)
    return render_template('view_post.html', post=post, can_moderate=can_moderate())


@app.route('/posts/<int:post_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_post(post_id):
    post = get_or_404(Post, post_id)
    if post.user_id != current_user.id:
        abort(403)
    if request.method == 'POST':
        title, content = _post_form_values()
        if not title or not content:
            flash('Заполните заголовок и текст', 'danger')
            return render_template('create_post.html', post=post, values=request.form)
        post.title, post.content = title, content
        if is_student():
            post.is_anonymous = bool(request.form.get('is_anonymous'))
        db.session.commit()
        flash('Пост обновлён', 'success')
        return redirect(url_for('view_post', post_id=post.id))
    return render_template('create_post.html', post=post, values={
        'title': post.title, 'content': post.content, 'is_anonymous': post.is_anonymous,
    })


@app.route('/posts/<int:post_id>/delete', methods=['POST'])
@login_required
def delete_post(post_id):
    post = get_or_404(Post, post_id)
    if post.user_id != current_user.id and not can_moderate():
        abort(403)
    db.session.delete(post)
    db.session.commit()
    flash('Пост удалён', 'success')
    return redirect(url_for('posts'))


@app.route('/posts/<int:post_id>/comment', methods=['POST'])
@login_required
def add_comment(post_id):
    post = get_or_404(Post, post_id)
    content = form_str('content', 5000)
    if not content:
        flash('Комментарий пустой', 'warning')
        return redirect(url_for('view_post', post_id=post.id))

    db.session.add(Comment(
        content=content,
        user_id=current_user.id,
        post_id=post.id,
        is_anonymous=is_student() and bool(request.form.get('is_anonymous')),
    ))
    db.session.commit()
    flash('Комментарий добавлен', 'success')
    return redirect(url_for('view_post', post_id=post.id) + '#comments')


@app.route('/comments/<int:comment_id>/delete', methods=['POST'])
@login_required
def delete_comment(comment_id):
    comment = get_or_404(Comment, comment_id)
    if comment.user_id != current_user.id and not can_moderate():
        abort(403)
    post_id = comment.post_id
    db.session.delete(comment)
    db.session.commit()
    flash('Комментарий удалён', 'success')
    return redirect(url_for('view_post', post_id=post_id) + '#comments')


# ---------- MESSAGES ----------


def build_conversations(user: User) -> list[dict]:
    """Список диалогов пользователя одним запросом (раньше — 2 запроса на каждого студента)."""
    msgs = (
        Message.query.filter(or_(Message.sender_id == user.id, Message.recipient_id == user.id))
        .order_by(Message.created_at.desc(), Message.id.desc())
        .all()
    )
    conversations: dict[tuple, dict] = {}
    for m in msgs:
        partner_id = m.recipient_id if m.sender_id == user.id else m.sender_id
        key = (partner_id, bool(m.is_anonymous))
        conv = conversations.get(key)
        if conv is None:
            conv = conversations[key] = {'partner_id': partner_id, 'anonymous': bool(m.is_anonymous),
                                         'last_message': m, 'unread': 0}
        if m.recipient_id == user.id and not m.is_read:
            conv['unread'] += 1

    partners = {u.id: u for u in User.query.filter(
        User.id.in_({c['partner_id'] for c in conversations.values()})
    ).all()} if conversations else {}

    # Сторона анонимного диалога определяется записью AnonThread, а не текущей ролью:
    # если психолога позже сделают студентом, он всё равно не должен увидеть имя.
    threads = {
        (t.student_id, t.psychologist_id): t
        for t in AnonThread.query.filter(
            or_(AnonThread.student_id == user.id, AnonThread.psychologist_id == user.id)
        ).all()
    }

    result = []
    for conv in conversations.values():
        partner = partners.get(conv['partner_id'])
        if partner is None:
            continue
        listener_thread = threads.get((partner.id, user.id))
        is_listener = conv['anonymous'] and (
            listener_thread is not None
            or ((user.id, partner.id) not in threads and user.role != 'student')
        )
        if is_listener:
            thread = listener_thread or services.get_anon_thread(partner.id, user.id)
            conv.update(title=thread.alias, avatar_user=None,
                        url=url_for('anon_thread', token=thread.token)
                        if user.role == 'psychologist' else None)
        elif conv['anonymous']:
            conv.update(title=f'{partner.display_name} · анонимно', avatar_user=partner,
                        url=url_for('anon_chat', psychologist_id=partner.id))
        else:
            conv.update(title=partner.display_name, avatar_user=partner,
                        url=url_for('chat', contact_id=partner.id))
        result.append(conv)
    db.session.commit()  # могли появиться новые AnonThread для старых анонимных сообщений
    return result


def _render_chat(partner: User, anonymous: bool, title: str, avatar_user, post_url: str):
    user = current_user

    if request.method == 'POST':
        if 'appointment_date' in request.form:
            if anonymous:
                abort(400)
            when = services.parse_local_datetime(request.form.get('appointment_date'))
            purpose = form_str('purpose', 1000)
            if when is None:
                flash('Укажите дату и время встречи', 'danger')
                return redirect(post_url)
            student, psychologist = (user, partner) if user.role == 'student' else (partner, user)
            appointment, error = services.schedule_appointment(student, psychologist, when, purpose, user)
            if error:
                flash(error, 'danger')
                return redirect(post_url)
            verb = 'Назначена встреча' if appointment.status == 'confirmed' else 'Запрос на встречу'
            _notify(user.id, partner.id,
                    f"{verb} на {when.strftime('%d.%m.%Y %H:%M')}. Цель: {purpose or 'не указана'}")
            db.session.commit()
            flash('Встреча назначена' if appointment.status == 'confirmed'
                  else 'Запрос отправлен психологу', 'success')
            return redirect(post_url)

        content = form_str('content')
        if not content:
            flash('Сообщение пустое', 'warning')
            return redirect(post_url)
        if len(content) > 5000:
            flash('Сообщение слишком длинное (максимум 5000 символов)', 'warning')
            return redirect(post_url)
        db.session.add(Message(
            content=content, sender_id=user.id, recipient_id=partner.id, is_anonymous=anonymous,
        ))
        db.session.commit()
        return redirect(post_url + '#bottom')

    thread_filter = services.thread_messages_filter(user.id, partner.id, anonymous)
    msgs = Message.query.filter(thread_filter).order_by(Message.created_at.asc(), Message.id.asc()).all()
    Message.query.filter(
        thread_filter, Message.recipient_id == user.id, Message.is_read.isnot(True)
    ).update({'is_read': True}, synchronize_session=False)
    db.session.commit()

    return render_template(
        'chat.html',
        conversations=build_conversations(user),
        partner=partner,
        anonymous=anonymous,
        chat_title=title,
        avatar_user=avatar_user,
        messages=msgs,
        post_url=post_url,
        active_url=post_url,
        psychologists=(
            User.query.filter_by(role='psychologist').order_by(User.full_name).all()
            if user.role == 'student' else []
        ),
    )


@app.route('/messages')
@login_required
def messages():
    if current_user.role not in ('student', 'psychologist'):
        flash('Сообщения доступны студентам и психологам', 'info')
        return redirect(url_for('dashboard'))
    psychologists = (
        User.query.filter_by(role='psychologist').order_by(User.full_name).all()
        if is_student() else []
    )
    return render_template(
        'messages.html',
        conversations=build_conversations(current_user),
        psychologists=psychologists,
        active_url=None,
    )


@app.route('/messages/<int:contact_id>', methods=['GET', 'POST'])
@login_required
def chat(contact_id):
    contact = get_or_404(User, contact_id)
    pair = {current_user.role, contact.role}
    if pair != {'student', 'psychologist'}:
        flash('Переписка возможна только между студентом и психологом', 'warning')
        return redirect(url_for('messages'))
    return _render_chat(contact, False, contact.display_name, contact,
                        url_for('chat', contact_id=contact.id))


@app.route('/messages/<int:psychologist_id>/anonymous', methods=['GET', 'POST'])
@roles_required('student')
def anon_chat(psychologist_id):
    psychologist = get_or_404(User, psychologist_id)
    if psychologist.role != 'psychologist':
        abort(404)
    return _render_chat(psychologist, True, f'{psychologist.display_name} · анонимный чат', psychologist,
                        url_for('anon_chat', psychologist_id=psychologist.id))


@app.route('/messages/anonymous/<token>', methods=['GET', 'POST'])
@roles_required('psychologist')
def anon_thread(token):
    thread = AnonThread.query.filter_by(token=token).first_or_404()
    if thread.psychologist_id != current_user.id:
        abort(404)
    student = get_or_404(User, thread.student_id)
    return _render_chat(student, True, thread.alias, None, url_for('anon_thread', token=thread.token))


# ---------- ARTICLES ----------


@app.route('/articles')
def articles():
    arts = Article.query.order_by(Article.created_at.desc()).all()
    return render_template('articles.html', articles=arts)


def _save_article(article: Article | None):
    title = form_str('title', 200)
    content = form_str('content', 100000)
    if not title or not content:
        flash('Заполните заголовок и текст статьи', 'danger')
        return None
    if article is None:
        article = Article(user_id=current_user.id)
        db.session.add(article)
    article.title, article.content = title, content

    folder = app.config['UPLOAD_FOLDER']
    file = request.files.get('image')
    if file and file.filename:
        try:
            filename = security.save_image(file, folder)
        except ValueError as e:
            db.session.rollback()
            flash(str(e), 'danger')
            return None
        security.remove_upload(folder, article.image_url)
        article.image_url = filename
    elif request.form.get('remove_image') and article.image_url:
        security.remove_upload(folder, article.image_url)
        article.image_url = None
    db.session.commit()
    return article


@app.route('/articles/create', methods=['GET', 'POST'])
@roles_required('psychologist')
def create_article():
    if request.method == 'POST':
        article = _save_article(None)
        if article:
            flash('Статья опубликована', 'success')
            return redirect(url_for('view_article', article_id=article.id))
        return render_template('create_article.html', article=None, values=request.form)
    return render_template('create_article.html', article=None, values={})


@app.route('/articles/<int:article_id>')
def view_article(article_id):
    article = get_or_404(Article, article_id)
    return render_template('view_article.html', article=article)


@app.route('/articles/<int:article_id>/edit', methods=['GET', 'POST'])
@roles_required('psychologist')
def edit_article(article_id):
    article = get_or_404(Article, article_id)
    if article.user_id != current_user.id:
        abort(403)
    if request.method == 'POST':
        if _save_article(article):
            flash('Статья обновлена', 'success')
            return redirect(url_for('view_article', article_id=article.id))
        return render_template('create_article.html', article=article, values=request.form)
    return render_template('create_article.html', article=article,
                           values={'title': article.title, 'content': article.content})


@app.route('/articles/<int:article_id>/delete', methods=['POST'])
@login_required
def delete_article(article_id):
    article = get_or_404(Article, article_id)
    if article.user_id != current_user.id and not is_admin_user():
        abort(403)
    security.remove_upload(app.config['UPLOAD_FOLDER'], article.image_url)
    db.session.delete(article)
    db.session.commit()
    flash('Статья удалена', 'success')
    return redirect(url_for('articles'))


# ---------- SEARCH / EMERGENCY / API ----------


@app.route('/search')
@login_required
def search():
    query = request.args.get('q', '').strip()[:100]
    if not query:
        return redirect(url_for('psychologists'))
    like = f'%{query}%'

    found_tests = Test.query.filter(
        Test.is_active.is_(True),
        or_(Test.title.ilike(like), Test.description.ilike(like),
            Test.title_kk.ilike(like), Test.description_kk.ilike(like)),
    ).all()
    found_articles = Article.query.filter(
        or_(Article.title.ilike(like), Article.content.ilike(like))
    ).order_by(Article.created_at.desc()).all()
    found_posts = Post.query.filter(
        or_(Post.title.ilike(like), Post.content.ilike(like))
    ).order_by(Post.created_at.desc()).limit(30).all()
    found_psychologists = User.query.filter(
        User.role == 'psychologist',
        or_(User.full_name.ilike(like), User.bio.ilike(like), User.username.ilike(like)),
    ).all()
    found_students = []
    if is_psychologist():
        found_students = (
            User.query.outerjoin(Group, Group.id == User.group_id)
            .filter(User.role == 'student',
                    or_(User.full_name.ilike(like), User.username.ilike(like), Group.name.ilike(like)))
            .order_by(User.full_name).limit(50).all()
        )

    return render_template(
        'search_results.html',
        query=query,
        tests=found_tests,
        articles=found_articles,
        posts=found_posts,
        psychologists=found_psychologists,
        students=found_students,
    )


@app.route('/emergency')
def emergency():
    return render_template('emergency.html')


@app.route('/privacy')
def privacy():
    return render_template('privacy.html')


@app.route('/favicon.ico')
def favicon():
    return redirect(url_for('static', filename='images/favicon.svg'), code=301)


@app.route('/api/messages/unread_count')
def unread_messages_count():
    if not current_user.is_authenticated:
        return jsonify({'count': 0})
    count = Message.query.filter_by(recipient_id=current_user.id, is_read=False).count()
    return jsonify({'count': count})


# =========================
#        ENTRYPOINT
# =========================

if __name__ == '__main__':
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    app.run(debug=_env_flag('FLASK_DEBUG'))
