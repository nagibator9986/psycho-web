# admin.py — SuperAdmin (email уникален; Flask 3.x; прочный CSV-импорт)
from __future__ import annotations

import csv
import io
import json
import base64
import re
import uuid
from datetime import datetime
from functools import wraps
from flask_login import current_user
from flask import (
    Blueprint, render_template, request, redirect, url_for,
    flash, session, current_app
)
from werkzeug.security import generate_password_hash
from sqlalchemy import or_, asc, desc, case

from extensions import db
from models import User, Group

admin_bp = Blueprint('admin', __name__, url_prefix='/admin')

ALLOWED_ROLES = ['student', 'psychologist', 'admin', 'superadmin']
EMAIL_RE = re.compile(r'^[^@\s]+@[^@\s]+\.[^@\s]+$')

# -------------------------------------------------
# Bootstrap superadmin (super / Azamat65)
# -------------------------------------------------
BOOTSTRAP_SUPERADMIN = {
    "username": "super",
    "email": "super@localhost",
    "password": "Azamat65",
}

def ensure_initial_superadmin() -> None:
    if User.query.filter_by(role='superadmin').first():
        return
    u = User.query.filter(
        (User.username == BOOTSTRAP_SUPERADMIN["username"]) |
        (User.email == BOOTSTRAP_SUPERADMIN["email"])
    ).first()
    password_hash = generate_password_hash(BOOTSTRAP_SUPERADMIN["password"])
    if u:
        u.role = 'superadmin'
        u.password = password_hash
    else:
        u = User(
            username=BOOTSTRAP_SUPERADMIN["username"],
            email=BOOTSTRAP_SUPERADMIN["email"],
            password=password_hash,
            role='superadmin',
            full_name='Super Admin',
            created_at=datetime.utcnow()
        )
        db.session.add(u)
    db.session.commit()
    print("✅ Bootstrap superadmin: super / Azamat65")

@admin_bp.before_app_request
def _bootstrap_superadmin_once():
    flag = "SUPERADMIN_BOOTSTRAPPED"
    if not current_app.config.get(flag):
        try:
            ensure_initial_superadmin()
        finally:
            current_app.config[flag] = True


# =========================
#     ACCESS DECORATOR
# =========================
def superadmin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated:
            flash('Нужно войти в систему', 'warning')
            return redirect(url_for('login'))

        if current_user.role not in ('admin', 'superadmin'):
            flash('Доступ запрещён', 'danger')
            return redirect(url_for('index'))

        return f(*args, **kwargs)
    return wrapper



# =========================
#         HELPERS
# =========================
def ensure_group(name: str, course: int | None = None):
    if not name:
        return None
    g = Group.query.filter_by(name=name).first()
    if not g:
        g = Group(name=name, course=course or 1)
        db.session.add(g)
        db.session.flush()
    else:
        if course and course > 0 and g.course != course:
            g.course = course
            db.session.flush()
    return g

def _decode_text(raw_bytes: bytes) -> tuple[str, str]:
    tried = []
    for enc in ('utf-8-sig', 'utf-8', 'cp1251', 'windows-1251'):
        try:
            return raw_bytes.decode(enc), enc
        except UnicodeDecodeError:
            tried.append(enc)
    raise UnicodeDecodeError("csv", b"", 0, 0, f"Не удалось декодировать CSV. Пробовали: {', '.join(tried)}")

def _detect_delimiter(text: str) -> str:
    sample = '\n'.join(text.splitlines()[:10])
    try:
        dialect = csv.Sniffer().sniff(sample, delimiters=[',', ';', '\t'])
        return dialect.delimiter
    except Exception:
        header = text.splitlines()[0] if text else ''
        if header.count(';') > header.count(','):
            return ';'
        if '\t' in header:
            return '\t'
        return ','

def _normalize_header(name: str) -> str:
    n = (name or '').strip().lower()
    mapping = {
        'fio': 'full_name', 'full name': 'full_name', 'фио': 'full_name',
        'iin': 'username', 'логин': 'username', 'user': 'username',
        'group_name': 'group', 'группа': 'group'
    }
    return mapping.get(n, n)

def _safe_int(s, default=1) -> int:
    try:
        v = int(float(s)) if s not in (None, '') else default
        return v if v > 0 else default
    except Exception:
        return default

def _build_error_csv(rows: list[dict]) -> str:
    out = io.StringIO()
    writer = csv.DictWriter(out, fieldnames=['line', 'username', 'email', 'reason'], delimiter=';')
    writer.writeheader()
    for r in rows:
        writer.writerow({
            'line': r.get('line'),
            'username': r.get('username', ''),
            'email': r.get('email', ''),
            'reason': r.get('reason', '')
        })
    out.seek(0)
    return out.getvalue()


# =========================
#        SUPERADMIN UI
# =========================
@admin_bp.route('/', methods=['GET'])
@superadmin_required
def superadmin_home():
    q = request.args.get('q', '').strip()
    role = request.args.get('role', '').strip()
    group = request.args.get('group', '').strip()
    sort = request.args.get('sort', 'date_desc')
    page = max(int(request.args.get('page', 1) or 1), 1)
    per_page = min(max(int(request.args.get('per_page', 20) or 20), 5), 100)

    query = User.query
    if q:
        like = f"%{q}%"
        query = query.filter(or_(User.username.ilike(like),
                                 User.email.ilike(like),
                                 User.full_name.ilike(like)))
    if role:
        query = query.filter(User.role == role)
    if group:
        query = query.join(Group, isouter=True).filter(Group.name == group)

    if sort == 'date_asc':
        query = query.order_by(asc(User.created_at))
    elif sort == 'name_asc':
        query = query.order_by(asc(User.full_name), asc(User.username))
    elif sort == 'name_desc':
        query = query.order_by(desc(User.full_name), desc(User.username))
    elif sort == 'group_asc':
        query = query.join(Group, isouter=True).order_by(
            asc(case((Group.name.is_(None), 1), else_=0)), asc(Group.name)
        )
    elif sort == 'group_desc':
        query = query.join(Group, isouter=True).order_by(
            asc(case((Group.name.is_(None), 1), else_=0)), desc(Group.name)
        )
    elif sort == 'role_asc':
        query = query.order_by(asc(User.role))
    elif sort == 'role_desc':
        query = query.order_by(desc(User.role))
    else:
        query = query.order_by(desc(User.created_at))

    total = query.count()
    users = query.limit(per_page).offset((page - 1) * per_page).all()

    roles = ALLOWED_ROLES
    groups = [g.name for g in Group.query.order_by(asc(Group.name)).all()]

    return render_template(
        'superadmin.html',
        users=users,
        total=total,
        page=page,
        per_page=per_page,
        q=q,
        role=role,
        group=group,
        sort=sort,
        roles=roles,
        groups=groups
    )


# =========================
#   CRUD / BULK ACTIONS
# =========================
@admin_bp.route('/users/create', methods=['POST'])
@superadmin_required
def create_user():
    username = (request.form.get('username') or '').strip()
    email = (request.form.get('email') or '').strip().lower()
    password = (request.form.get('password') or '').strip()
    role = (request.form.get('role') or 'student').strip()
    full_name = (request.form.get('full_name') or '').strip()
    group_name = (request.form.get('group') or '').strip()
    course = request.form.get('course', type=int)

    if not username or not email:
        flash('Нужно указать username и email', 'warning')
        return redirect(url_for('admin.superadmin_home'))
    if not EMAIL_RE.match(email):
        flash('Некорректный email', 'danger')
        return redirect(url_for('admin.superadmin_home'))
    if role not in ALLOWED_ROLES:
        flash('Неверная роль', 'danger')
        return redirect(url_for('admin.superadmin_home'))
    if User.query.filter_by(username=username).first():
        flash('Имя пользователя занято', 'danger')
        return redirect(url_for('admin.superadmin_home'))
    if User.query.filter_by(email=email).first():
        flash('Email уже используется другим аккаунтом', 'danger')
        return redirect(url_for('admin.superadmin_home'))

    if not password:
        password = uuid.uuid4().hex[:10]

    grp = ensure_group(group_name, course)
    u = User(
        username=username,
        email=email,
        password=generate_password_hash(password),
        role=role,
        full_name=full_name or None,
        group_id=grp.id if grp else None,
        created_at=datetime.utcnow()
    )
    db.session.add(u)
    db.session.commit()

    flash(f'Пользователь {username} создан', 'success')
    return redirect(url_for('admin.superadmin_home'))


@admin_bp.route('/users/<int:user_id>/update', methods=['POST'])
@superadmin_required
def update_user(user_id):
    u = User.query.get_or_404(user_id)

    new_role = (request.form.get('role') or u.role).strip()
    new_full = (request.form.get('full_name') or u.full_name or '').strip()
    new_email = (request.form.get('email') or u.email).strip().lower()
    new_group = (request.form.get('group') or '').strip()
    course = request.form.get('course', type=int)
    new_password = (request.form.get('password') or '').strip()

    if new_role not in ALLOWED_ROLES:
        flash('Неверная роль', 'danger')
        return redirect(url_for('admin.superadmin_home'))
    if not EMAIL_RE.match(new_email):
        flash('Некорректный email', 'danger')
        return redirect(url_for('admin.superadmin_home'))
    if new_email != u.email:
        if User.query.filter(User.email == new_email, User.id != u.id).first():
            flash('Этот email уже используется другим аккаунтом', 'danger')
            return redirect(url_for('admin.superadmin_home'))

    u.role = new_role
    u.full_name = new_full or None
    u.email = new_email

    grp = ensure_group(new_group, course)
    u.group_id = grp.id if grp else None

    if new_password:
        u.password = generate_password_hash(new_password)

    db.session.commit()
    flash('Профиль обновлён', 'success')
    return redirect(url_for('admin.superadmin_home'))


@admin_bp.route('/users/<int:user_id>/delete', methods=['POST'])
@superadmin_required
def delete_user(user_id):
    u = User.query.get_or_404(user_id)
    if u.id == session.get('user_id'):
        flash('Нельзя удалить собственный аккаунт супер-админа', 'warning')
        return redirect(url_for('admin.superadmin_home'))
    db.session.delete(u)
    db.session.commit()
    flash('Пользователь удалён', 'success')
    return redirect(url_for('admin.superadmin_home'))


@admin_bp.route('/users/bulk_delete', methods=['POST'])
@superadmin_required
def bulk_delete():
    ids = request.form.getlist('user_ids[]')
    if not ids:
        flash('Не выбраны пользователи', 'warning')
        return redirect(url_for('admin.superadmin_home'))

    sid = str(session.get('user_id'))  # защита от самоудаления
    ids = [i for i in ids if i != sid]

    deleted = 0
    for s in ids:
        try:
            u = User.query.get(int(s))
            if u:
                db.session.delete(u)
                deleted += 1
        except ValueError:
            continue
    db.session.commit()
    flash(f'Удалено пользователей: {deleted}', 'success')
    return redirect(url_for('admin.superadmin_home'))


# =========================
#     BULK CSV IMPORT
# =========================
@admin_bp.route('/users/bulk_upload', methods=['POST'])
@superadmin_required
def bulk_upload():
    """
    Шаг 1: парсим CSV и строим план (create/update/skip) + собираем ошибки.
    Шаг 2: confirm=1 применяем план транзакционно (no_autoflush + commit/rollback).
    Правила: username и email — уникальны в БД.
    """
    mode = (request.form.get('mode') or 'create_only').strip()
    if mode not in ('create_only', 'upsert'):
        mode = 'create_only'

    # ===== ШАГ 2: подтверждение плана =====
    if request.form.get('confirm') == '1':
        plan_b64 = request.form.get('plan_b64', '')
        if not plan_b64:
            flash('План импорта отсутствует. Повторите загрузку CSV.', 'danger')
            return redirect(url_for('admin.superadmin_home'))
        try:
            plan_json = base64.b64decode(plan_b64.encode('utf-8')).decode('utf-8')
            plan = json.loads(plan_json)
        except Exception:
            flash('План импорта повреждён. Повторите загрузку CSV.', 'danger')
            return redirect(url_for('admin.superadmin_home'))

        created = updated = skipped = 0
        errors = []

        try:
            with db.session.no_autoflush:
                for item in plan.get('items', []):
                    action = item.get('action')
                    if action not in ('create', 'update', 'skip', 'error'):
                        continue
                    if action in ('skip', 'error'):
                        skipped += 1
                        continue

                    d = item['data']
                    username = d['username']
                    email    = (d['email'] or '').lower()
                    fullnm   = d.get('full_name')
                    role     = d.get('role') or 'student'
                    groupnm  = d.get('group')
                    course   = _safe_int(d.get('course'), 1)
                    password = d.get('password') or f'{username}abc'

                    grp = ensure_group(groupnm, course) if groupnm else None

                    if action == 'create':
                        # финальная проверка уникальности перед INSERT
                        if User.query.filter_by(username=username).first():
                            errors.append({'line': item.get('line', '-'), 'username': username, 'email': email,
                                           'reason': 'Создание отменено: username уже существует'})
                            skipped += 1
                            continue
                        if User.query.filter_by(email=email).first():
                            errors.append({'line': item.get('line', '-'), 'username': username, 'email': email,
                                           'reason': 'Создание отменено: email уже существует'})
                            skipped += 1
                            continue

                        user = User(
                            username=username,
                            email=email,
                            password=generate_password_hash(password),
                            role=role if role in ALLOWED_ROLES else 'student',
                            full_name=fullnm or None,
                            group_id=grp.id if grp else None,
                            created_at=datetime.utcnow()
                        )
                        db.session.add(user)
                        created += 1

                    elif action == 'update' and mode == 'upsert':
                        user = User.query.filter_by(username=username).first()
                        if not user:
                            # если в промежутке удалён — пробуем создать, но email должен быть свободен
                            if User.query.filter_by(email=email).first():
                                errors.append({'line': item.get('line', '-'), 'username': username, 'email': email,
                                               'reason': 'Создание вместо update невозможно: email уже существует'})
                                skipped += 1
                                continue
                            user = User(
                                username=username,
                                email=email,
                                password=generate_password_hash(password),
                                role=role if role in ALLOWED_ROLES else 'student',
                                full_name=fullnm or None,
                                group_id=grp.id if grp else None,
                                created_at=datetime.utcnow()
                            )
                            db.session.add(user)
                            created += 1
                        else:
                            # если меняем email — он должен быть свободен у других
                            if email and email != user.email:
                                if User.query.filter(User.email == email, User.id != user.id).first():
                                    errors.append({'line': item.get('line', '-'), 'username': username, 'email': email,
                                                   'reason': 'Update отменён: email занят другим пользователем'})
                                    skipped += 1
                                    continue
                                user.email = email

                            if fullnm:
                                user.full_name = fullnm
                            if role in ALLOWED_ROLES:
                                user.role = role
                            user.group_id = grp.id if grp else None
                            if d.get('password'):
                                user.password = generate_password_hash(password)
                            updated += 1

            db.session.commit()

        except Exception as e:
            db.session.rollback()
            errors.append({'line': '-', 'username': '-', 'email': '-', 'reason': f'DB error: {e}'})
            error_csv = _build_error_csv(errors)
            return render_template(
                'bulk_upload_result.html',
                mode=mode,
                created=0, updated=0, skipped=skipped,
                errors=errors, error_csv=error_csv
            )

        error_csv = _build_error_csv(errors) if errors else ''
        return render_template(
            'bulk_upload_result.html',
            mode=mode,
            created=created, updated=updated, skipped=skipped,
            errors=errors, error_csv=error_csv
        )

    # ===== ШАГ 1: парсинг CSV и построение плана =====
    file = request.files.get('csv')
    if not file or file.filename == '':
        flash('Прикрепите CSV-файл', 'warning')
        return redirect(url_for('admin.superadmin_home'))

    try:
        text, enc = _decode_text(file.read())
    except UnicodeDecodeError as e:
        flash(str(e), 'danger')
        return redirect(url_for('admin.superadmin_home'))

    delimiter = _detect_delimiter(text)
    reader = csv.DictReader(io.StringIO(text), delimiter=delimiter)

    if not reader.fieldnames:
        flash('В CSV нет заголовка (первой строки).', 'danger')
        return redirect(url_for('admin.superadmin_home'))
    normalized_fieldnames = [_normalize_header(x) for x in reader.fieldnames]
    header_map = {src: norm for src, norm in zip(reader.fieldnames, normalized_fieldnames)}

    need_min = {'username', 'email'}
    have = set(header_map.values())
    if not need_min.issubset(have):
        flash('Нужны как минимум колонки: username, email (остальные опциональны).', 'danger')
        return redirect(url_for('admin.superadmin_home'))

    rows = []
    for i, raw_row in enumerate(reader, start=2):
        row = {}
        for src_key, val in raw_row.items():
            norm_key = header_map.get(src_key, src_key)
            row[norm_key] = (val or '').strip()
        rows.append((i, row))

    # Предзагрузка существующих username/email для быстрых проверок
    existing_usernames = set(x[0] for x in db.session.query(User.username).all())
    existing_emails = set(x[0] for x in db.session.query(User.email).all())

    seen_usernames, seen_emails = set(), set()
    plan_items, errors = [], []
    created = updated = skipped = 0

    for lineno, r in rows:
        username = (r.get('username') or '')
        email = (r.get('email') or '').lower()
        fullnm = r.get('full_name') or r.get('fio') or ''
        role = (r.get('role') or 'student').strip()
        groupnm = r.get('group') or r.get('group_name') or ''
        course = _safe_int(r.get('course'), 1)
        password = r.get('password') or ''

        # базовая валидация
        if not username:
            errors.append({'line': lineno, 'username': '', 'email': email, 'reason': 'Пустой username'})
            skipped += 1
            continue
        if not email or not EMAIL_RE.match(email):
            errors.append({'line': lineno, 'username': username, 'email': email, 'reason': 'Некорректный email'})
            skipped += 1
            continue
        if role and role not in ALLOWED_ROLES:
            errors.append({'line': lineno, 'username': username, 'email': email, 'reason': f'Неизвестная роль "{role}"'})
            skipped += 1
            continue

        # дубликаты в файле
        if username in seen_usernames:
            errors.append({'line': lineno, 'username': username, 'email': email, 'reason': 'Дубликат username в файле'})
            skipped += 1
            continue
        if email in seen_emails:
            errors.append({'line': lineno, 'username': username, 'email': email, 'reason': 'Дубликат email в файле'})
            skipped += 1
            continue
        seen_usernames.add(username)
        seen_emails.add(email)

        # существование в БД (учитывая уникальный email)
        username_exists = username in existing_usernames
        email_exists = email in existing_emails

        if username_exists:
            if mode == 'upsert':
                plan_items.append({
                    'line': lineno,
                    'action': 'update',
                    'data': {
                        'username': username, 'email': email, 'full_name': fullnm,
                        'role': role or 'student', 'group': groupnm, 'course': course,
                        'password': password
                    }
                })
                updated += 1
            else:
                plan_items.append({
                    'line': lineno,
                    'action': 'skip',
                    'reason': 'Уже существует (режим create_only, совпал username)',
                    'data': {'username': username, 'email': email}
                })
                skipped += 1
        else:
            if email_exists:
                # создать нельзя из-за уникального email — фиксируем ошибку
                errors.append({'line': lineno, 'username': username, 'email': email, 'reason': 'Email уже существует в БД'})
                skipped += 1
                plan_items.append({
                    'line': lineno,
                    'action': 'error',
                    'reason': 'Email уже существует в БД',
                    'data': {'username': username, 'email': email}
                })
            else:
                plan_items.append({
                    'line': lineno,
                    'action': 'create',
                    'data': {
                        'username': username, 'email': email, 'full_name': fullnm,
                        'role': role or 'student', 'group': groupnm, 'course': course,
                        'password': password
                    }
                })
                created += 1

    error_csv = _build_error_csv(errors) if errors else ''
    plan_payload = {'mode': mode, 'items': plan_items}
    plan_b64 = base64.b64encode(json.dumps(plan_payload, ensure_ascii=False).encode('utf-8')).decode('utf-8')

    return render_template(
        'bulk_upload_preview.html',
        mode=mode,
        delimiter=delimiter,
        created=created, updated=updated, skipped=skipped,
        errors=errors,
        error_csv=error_csv,
        plan_b64=plan_b64,
        sample_items=plan_items[:50]
    )


# =========================
#     QUICK ROLE CHANGE
# =========================
@admin_bp.route(
    '/users/<int:user_id>/role',
    methods=['POST'],
    endpoint='change_role'  # Явное имя endpoint для url_for('admin.change_role', user_id=...)
)
@superadmin_required
def change_role(user_id):
    """Смена роли из списка на странице."""
    role = (request.form.get('role') or '').strip()
    if role not in ALLOWED_ROLES:
        flash('Неверная роль', 'danger')
        return redirect(url_for('admin.superadmin_home'))
    u = User.query.get_or_404(user_id)
    u.role = role
    db.session.commit()
    flash('Роль обновлена', 'success')
    return redirect(url_for('admin.superadmin_home'))
