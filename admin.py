# admin.py — панель администратора: пользователи, группы, массовый импорт CSV
from __future__ import annotations

import base64
import csv
import io
import json
import re
import secrets
from datetime import datetime
from functools import wraps

from flask import Blueprint, abort, current_app, flash, redirect, render_template, request, url_for
from flask_login import current_user
from sqlalchemy import asc, case, desc, func, or_
from sqlalchemy.orm import joinedload
from werkzeug.security import generate_password_hash

import security
import services
from extensions import db
from models import Group, Test, TestResult, User

admin_bp = Blueprint('admin', __name__, url_prefix='/admin')

ALLOWED_ROLES = ['student', 'psychologist', 'admin', 'superadmin']
EMAIL_RE = re.compile(r'^[^@\s]+@[^@\s]+\.[^@\s]+$')
USERNAME_RE = re.compile(r'[A-Za-z0-9_.\-@]{3,80}')


# =========================
#     ACCESS
# =========================
def superadmin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated:
            flash('Нужно войти в систему', 'warning')
            return redirect(url_for('login', next=request.path))
        if current_user.role not in ('admin', 'superadmin'):
            abort(403)
        return f(*args, **kwargs)
    return wrapper


def assignable_roles() -> list[str]:
    """Админ управляет студентами и психологами; суперадмин — всеми."""
    if current_user.role == 'superadmin':
        return ALLOWED_ROLES
    return ['student', 'psychologist']


def can_manage(user: User) -> bool:
    return current_user.role == 'superadmin' or user.role in ('student', 'psychologist')


def _back():
    target = request.form.get('next')
    if security.is_safe_next(target):
        return redirect(target)
    return redirect(url_for('admin.superadmin_home'))


def _new_password() -> str:
    return secrets.token_urlsafe(9)


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
    elif course and course > 0 and g.course != course:
        g.course = course
        db.session.flush()
    return g


def _decode_text(raw_bytes: bytes) -> tuple[str, str]:
    for enc in ('utf-8-sig', 'cp1251'):
        try:
            return raw_bytes.decode(enc), enc
        except UnicodeDecodeError:
            continue
    raise UnicodeDecodeError('csv', b'', 0, 0, 'Не удалось прочитать CSV: сохраните его в UTF-8')


def _detect_delimiter(text: str) -> str:
    sample = '\n'.join(text.splitlines()[:10])
    try:
        return csv.Sniffer().sniff(sample, delimiters=[',', ';', '\t']).delimiter
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
        'iin': 'username', 'иин': 'username', 'логин': 'username', 'user': 'username',
        'group_name': 'group', 'группа': 'group', 'курс': 'course', 'роль': 'role',
        'пароль': 'password', 'почта': 'email',
    }
    return mapping.get(n, n)


def _safe_int(s, default=1) -> int:
    try:
        v = int(float(s)) if s not in (None, '') else default
        return v if v > 0 else default
    except Exception:
        return default


def _build_csv(rows: list[dict], fields: list[str]) -> str:
    out = io.StringIO()
    writer = csv.DictWriter(out, fieldnames=fields, delimiter=';', extrasaction='ignore')
    writer.writeheader()
    for r in rows:
        writer.writerow({k: services.csv_safe(v) for k, v in r.items()})
    return '﻿' + out.getvalue()


def _build_error_csv(rows: list[dict]) -> str:
    return _build_csv(rows, ['line', 'username', 'email', 'reason'])


# =========================
#        SUPERADMIN UI
# =========================
SORTS = {
    'date_asc': [asc(User.created_at)],
    'date_desc': [desc(User.created_at)],
    'name_asc': [asc(User.full_name), asc(User.username)],
    'name_desc': [desc(User.full_name), desc(User.username)],
    'group_asc': [asc(case((Group.name.is_(None), 1), else_=0)), asc(Group.name)],
    'group_desc': [asc(case((Group.name.is_(None), 1), else_=0)), desc(Group.name)],
    'role_asc': [asc(User.role)],
    'role_desc': [desc(User.role)],
}


@admin_bp.route('/', methods=['GET'])
@superadmin_required
def superadmin_home():
    q = request.args.get('q', '').strip()
    role = request.args.get('role', '').strip()
    group = request.args.get('group', '').strip()
    sort = request.args.get('sort', 'date_desc')
    if sort not in SORTS:
        sort = 'date_desc'
    page = max(request.args.get('page', 1, type=int) or 1, 1)
    per_page = min(max(request.args.get('per_page', 20, type=int) or 20, 5), 100)

    # одна внешняя связь с группами — раньше фильтр и сортировка по группе
    # присоединяли таблицу дважды и запрос падал
    query = User.query.outerjoin(Group, Group.id == User.group_id).options(joinedload(User.group))
    if q:
        like = f'%{q}%'
        query = query.filter(or_(User.username.ilike(like), User.email.ilike(like), User.full_name.ilike(like)))
    if role:
        query = query.filter(User.role == role)
    if group:
        query = query.filter(Group.name == group)

    total = query.count()
    users = query.order_by(*SORTS[sort]).limit(per_page).offset((page - 1) * per_page).all()
    pages = max((total + per_page - 1) // per_page, 1)

    stats = dict(db.session.query(User.role, func.count(User.id)).group_by(User.role).all())
    stats['results'] = TestResult.query.count()
    stats['tests'] = Test.query.count()

    return render_template(
        'superadmin.html',
        users=users,
        total=total,
        page=page,
        pages=pages,
        per_page=per_page,
        q=q,
        role=role,
        group=group,
        sort=sort,
        roles=ALLOWED_ROLES,
        assignable=assignable_roles(),
        groups=[g.name for g in Group.query.order_by(asc(Group.name)).all()],
        stats=stats,
        can_manage=can_manage,
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
        flash('Нужно указать логин и email', 'warning')
        return _back()
    if not USERNAME_RE.fullmatch(username):
        flash('Логин: 3–80 символов, латиница, цифры, точка, дефис, подчёркивание', 'danger')
        return _back()
    if not EMAIL_RE.match(email):
        flash('Некорректный email', 'danger')
        return _back()
    if role not in assignable_roles():
        flash('Эту роль вы назначить не можете', 'danger')
        return _back()
    if User.query.filter_by(username=username).first():
        flash('Логин занят', 'danger')
        return _back()
    if User.query.filter_by(email=email).first():
        flash('Email уже используется другим аккаунтом', 'danger')
        return _back()

    generated = not password
    if generated:
        password = _new_password()

    grp = ensure_group(group_name, course)
    u = User(
        username=username,
        email=email,
        password=generate_password_hash(password),
        role=role,
        full_name=full_name or None,
        group_id=grp.id if grp else None,
        created_at=datetime.utcnow(),
        # пароль знает администратор — пользователь сменит его при первом входе
        must_change_password=True,
    )
    db.session.add(u)
    db.session.commit()

    if generated:
        flash(f'Пользователь {username} создан. Временный пароль: {password} — '
              'передайте его пользователю, при входе он задаст свой.', 'success')
    else:
        flash(f'Пользователь {username} создан', 'success')
    return _back()


@admin_bp.route('/users/<int:user_id>/update', methods=['POST'])
@superadmin_required
def update_user(user_id):
    u = db.session.get(User, user_id) or abort(404)
    if not can_manage(u) and u.id != current_user.id:
        abort(403)

    new_role = (request.form.get('role') or u.role).strip()
    new_full = (request.form.get('full_name') or u.full_name or '').strip()
    new_email = (request.form.get('email') or u.email).strip().lower()
    new_group = (request.form.get('group') or '').strip()
    course = request.form.get('course', type=int)
    new_password = (request.form.get('password') or '').strip()

    if new_role != u.role and new_role not in assignable_roles():
        flash('Эту роль вы назначить не можете', 'danger')
        return _back()
    if u.id == current_user.id and new_role != u.role:
        flash('Свою роль поменять нельзя', 'warning')
        return _back()
    if not EMAIL_RE.match(new_email):
        flash('Некорректный email', 'danger')
        return _back()
    if new_email != u.email and User.query.filter(User.email == new_email, User.id != u.id).first():
        flash('Этот email уже используется другим аккаунтом', 'danger')
        return _back()

    u.role = new_role
    u.full_name = new_full or None
    u.email = new_email

    grp = ensure_group(new_group, course)
    u.group_id = grp.id if grp else None

    if new_password:
        problem = security.password_problem(new_password)
        if problem:
            db.session.rollback()
            flash(problem, 'danger')
            return _back()
        u.password = generate_password_hash(new_password)
        u.must_change_password = u.id != current_user.id

    db.session.commit()
    flash('Профиль обновлён', 'success')
    return _back()


@admin_bp.route('/users/<int:user_id>/reset_password', methods=['POST'])
@superadmin_required
def reset_password(user_id):
    u = db.session.get(User, user_id) or abort(404)
    if not can_manage(u) or u.id == current_user.id:
        abort(403)
    password = _new_password()
    u.password = generate_password_hash(password)
    u.must_change_password = True
    db.session.commit()
    flash(f'Временный пароль для {u.username}: {password} — при входе пользователь задаст свой', 'success')
    return _back()


def _delete_one(u: User) -> str | None:
    """Удаляет пользователя с данными; возвращает текст ошибки или None."""
    if u.id == current_user.id:
        return 'Нельзя удалить собственный аккаунт'
    if not can_manage(u):
        return f'Недостаточно прав, чтобы удалить {u.username}'
    blocker = services.user_delete_blocker(u)
    if blocker:
        return blocker
    pic = u.profile_pic
    services.delete_user_with_data(u)
    security.remove_upload(current_app.config['UPLOAD_FOLDER'], pic)
    return None


@admin_bp.route('/users/<int:user_id>/delete', methods=['POST'])
@superadmin_required
def delete_user(user_id):
    u = db.session.get(User, user_id) or abort(404)
    error = _delete_one(u)
    if error:
        flash(error, 'warning')
        return _back()
    db.session.commit()
    flash('Пользователь и его данные удалены', 'success')
    return _back()


@admin_bp.route('/users/bulk_delete', methods=['POST'])
@superadmin_required
def bulk_delete():
    ids = request.form.getlist('user_ids[]')
    if not ids:
        flash('Не выбраны пользователи', 'warning')
        return _back()

    deleted, problems = 0, []
    for s in ids:
        try:
            u = db.session.get(User, int(s))
        except ValueError:
            continue
        if u is None:
            continue
        error = _delete_one(u)
        if error:
            problems.append(error)
        else:
            deleted += 1
    db.session.commit()
    flash(f'Удалено пользователей: {deleted}', 'success')
    for p in problems[:5]:
        flash(p, 'warning')
    return _back()


# =========================
#     GROUPS
# =========================
@admin_bp.route('/groups', methods=['GET'])
@superadmin_required
def groups():
    rows = (
        db.session.query(Group, func.count(User.id))
        .outerjoin(User, User.group_id == Group.id)
        .group_by(Group.id)
        .order_by(Group.course.asc(), Group.name.asc())
        .all()
    )
    return render_template('admin_groups.html', rows=rows)


@admin_bp.route('/groups/create', methods=['POST'])
@superadmin_required
def group_create():
    name = (request.form.get('name') or '').strip()[:100]
    course = _safe_int(request.form.get('course'), 1)
    if not name:
        flash('Укажите название группы', 'warning')
    elif Group.query.filter_by(name=name).first():
        flash('Такая группа уже есть', 'warning')
    else:
        db.session.add(Group(name=name, course=course))
        db.session.commit()
        flash(f'Группа {name} создана', 'success')
    return redirect(url_for('admin.groups'))


@admin_bp.route('/groups/<int:group_id>/update', methods=['POST'])
@superadmin_required
def group_update(group_id):
    g = db.session.get(Group, group_id) or abort(404)
    name = (request.form.get('name') or '').strip()[:100]
    course = _safe_int(request.form.get('course'), g.course)
    if not name:
        flash('Название не может быть пустым', 'warning')
        return redirect(url_for('admin.groups'))
    if name != g.name and Group.query.filter_by(name=name).first():
        flash('Группа с таким названием уже есть', 'warning')
        return redirect(url_for('admin.groups'))
    g.name, g.course = name, course
    db.session.commit()
    flash('Группа обновлена', 'success')
    return redirect(url_for('admin.groups'))


@admin_bp.route('/groups/<int:group_id>/delete', methods=['POST'])
@superadmin_required
def group_delete(group_id):
    g = db.session.get(Group, group_id) or abort(404)
    members = User.query.filter_by(group_id=g.id).count()
    if members:
        flash(f'В группе {members} пользователей — сначала переведите их в другую группу', 'warning')
        return redirect(url_for('admin.groups'))
    db.session.delete(g)
    db.session.commit()
    flash('Группа удалена', 'success')
    return redirect(url_for('admin.groups'))


# =========================
#     BULK CSV IMPORT
# =========================
@admin_bp.route('/users/bulk_upload', methods=['POST'])
@superadmin_required
def bulk_upload():
    """
    Шаг 1: парсим CSV и строим план (create/update/skip) + собираем ошибки.
    Шаг 2: confirm=1 применяем план транзакционно.
    Если пароль в файле не указан, генерируется случайный: список логинов и
    паролей выдаётся файлом после импорта. Раньше пароль был «ИИН + abc» —
    его легко угадать, зная ИИН.
    """
    mode = (request.form.get('mode') or 'create_only').strip()
    if mode not in ('create_only', 'upsert'):
        mode = 'create_only'
    allowed = assignable_roles()

    # ===== ШАГ 2: подтверждение плана =====
    if request.form.get('confirm') == '1':
        try:
            plan = json.loads(base64.b64decode(request.form.get('plan_b64', '').encode()).decode('utf-8'))
        except Exception:
            flash('План импорта повреждён. Повторите загрузку CSV.', 'danger')
            return redirect(url_for('admin.superadmin_home'))

        created = updated = skipped = 0
        errors, credentials = [], []
        # какие колонки были в файле: отсутствующие при обновлении не трогаем
        columns = set(plan.get('columns') or [])

        def fail(item, username, email, reason):
            errors.append({'line': item.get('line', '-'), 'username': username, 'email': email, 'reason': reason})

        try:
            with db.session.no_autoflush:
                for item in plan.get('items', []):
                    action = item.get('action')
                    if action not in ('create', 'update'):
                        skipped += 1
                        continue

                    d = item.get('data') or {}
                    username = str(d.get('username') or '')
                    email = str(d.get('email') or '').lower()
                    fullnm = d.get('full_name')
                    role = d.get('role') or ''
                    # план пришёл из формы — проверяем данные ещё раз
                    if not USERNAME_RE.fullmatch(username) or not EMAIL_RE.match(email):
                        fail(item, username, email, 'Некорректный логин или email')
                        skipped += 1
                        continue
                    if role and role not in allowed:
                        fail(item, username, email, f'Роль «{role}» вам назначать нельзя')
                        skipped += 1
                        continue
                    groupnm = d.get('group') or ''
                    # нет курса в файле — курс существующей группы не меняем
                    course = _safe_int(d.get('course'), 0) or None
                    given_password = d.get('password') or ''

                    grp = ensure_group(groupnm, course) if groupnm else None
                    user = User.query.filter_by(username=username).first()

                    if user is not None and user.id == current_user.id:
                        fail(item, username, email, 'Свой аккаунт через импорт не изменяется')
                        skipped += 1
                        continue

                    if action == 'update' and mode == 'upsert' and user is not None:
                        if not can_manage(user):
                            fail(item, username, email, 'Недостаточно прав для изменения этого аккаунта')
                            skipped += 1
                            continue
                        if email and email != user.email:
                            if User.query.filter(User.email == email, User.id != user.id).first():
                                fail(item, username, email, 'Email занят другим пользователем')
                                skipped += 1
                                continue
                            user.email = email
                        if fullnm:
                            user.full_name = fullnm
                        if 'role' in columns and role:
                            user.role = role
                        if 'group' in columns and grp is not None:
                            user.group_id = grp.id
                        if given_password:
                            user.password = generate_password_hash(given_password)
                            user.must_change_password = True
                        updated += 1
                        continue

                    if user is not None:
                        fail(item, username, email, 'Логин уже существует')
                        skipped += 1
                        continue
                    if User.query.filter_by(email=email).first():
                        fail(item, username, email, 'Email уже существует')
                        skipped += 1
                        continue

                    password = given_password or _new_password()
                    db.session.add(User(
                        username=username,
                        email=email,
                        password=generate_password_hash(password),
                        role=role or 'student',
                        full_name=fullnm or None,
                        group_id=grp.id if grp else None,
                        created_at=datetime.utcnow(),
                        must_change_password=True,
                    ))
                    if not given_password:
                        credentials.append({
                            'username': username, 'password': password, 'full_name': fullnm or '',
                            'group': groupnm or '',
                        })
                    created += 1

            db.session.commit()

        except Exception as e:
            db.session.rollback()
            errors.append({'line': '-', 'username': '-', 'email': '-', 'reason': f'Ошибка БД: {e}'})
            return render_template(
                'bulk_upload_result.html', mode=mode, created=0, updated=0, skipped=skipped,
                errors=errors, error_csv=_build_error_csv(errors), credentials_csv='', credentials_count=0,
            )

        return render_template(
            'bulk_upload_result.html',
            mode=mode, created=created, updated=updated, skipped=skipped,
            errors=errors, error_csv=_build_error_csv(errors) if errors else '',
            credentials_csv=_build_csv(credentials, ['username', 'password', 'full_name', 'group'])
            if credentials else '',
            credentials_count=len(credentials),
        )

    # ===== ШАГ 1: парсинг CSV и построение плана =====
    file = request.files.get('csv')
    if not file or file.filename == '':
        flash('Прикрепите CSV-файл', 'warning')
        return redirect(url_for('admin.superadmin_home'))

    try:
        text, _enc = _decode_text(file.read())
    except UnicodeDecodeError as e:
        flash(str(e.reason), 'danger')
        return redirect(url_for('admin.superadmin_home'))

    delimiter = _detect_delimiter(text)
    reader = csv.DictReader(io.StringIO(text), delimiter=delimiter)

    if not reader.fieldnames:
        flash('В CSV нет заголовка (первой строки).', 'danger')
        return redirect(url_for('admin.superadmin_home'))
    header_map = {src: _normalize_header(src) for src in reader.fieldnames}

    if not {'username', 'email'}.issubset(set(header_map.values())):
        flash('Нужны как минимум колонки: username, email (остальные опциональны).', 'danger')
        return redirect(url_for('admin.superadmin_home'))

    rows = []
    for i, raw_row in enumerate(reader, start=2):
        row = {header_map.get(k, k): (v or '').strip() for k, v in raw_row.items() if k is not None}
        if any(row.values()):
            rows.append((i, row))

    existing_usernames = {x[0] for x in db.session.query(User.username).all()}
    existing_emails = {x[0] for x in db.session.query(User.email).all()}

    seen_usernames, seen_emails = set(), set()
    plan_items, errors = [], []
    created = updated = skipped = 0

    for lineno, r in rows:
        username = r.get('username') or ''
        email = (r.get('email') or '').lower()
        role = (r.get('role') or 'student').strip()

        def err(reason):
            errors.append({'line': lineno, 'username': username, 'email': email, 'reason': reason})

        if not username:
            err('Пустой username')
        elif not USERNAME_RE.fullmatch(username):
            err('Недопустимые символы в username')
        elif not email or not EMAIL_RE.match(email):
            err('Некорректный email')
        elif role not in ALLOWED_ROLES:
            err(f'Неизвестная роль «{role}»')
        elif role not in allowed:
            err(f'Роль «{role}» вам назначать нельзя')
        elif username in seen_usernames:
            err('Дубликат username в файле')
        elif email in seen_emails:
            err('Дубликат email в файле')
        else:
            seen_usernames.add(username)
            seen_emails.add(email)
            data = {
                'username': username, 'email': email, 'full_name': r.get('full_name') or '',
                'role': (r.get('role') or '').strip(), 'group': r.get('group') or '',
                'course': _safe_int(r.get('course'), 0) or '',
                'password': r.get('password') or '',
            }
            if username in existing_usernames:
                if mode == 'upsert':
                    plan_items.append({'line': lineno, 'action': 'update', 'data': data})
                    updated += 1
                else:
                    plan_items.append({'line': lineno, 'action': 'skip', 'data': data})
                    skipped += 1
            elif email in existing_emails:
                err('Email уже существует в БД')
            else:
                plan_items.append({'line': lineno, 'action': 'create', 'data': data})
                created += 1
            continue
        skipped += 1

    plan_b64 = base64.b64encode(
        json.dumps({'mode': mode, 'columns': sorted(set(header_map.values())), 'items': plan_items},
                   ensure_ascii=False).encode('utf-8')
    ).decode('utf-8')

    return render_template(
        'bulk_upload_preview.html',
        mode=mode,
        delimiter=delimiter,
        created=created, updated=updated, skipped=skipped,
        errors=errors,
        error_csv=_build_error_csv(errors) if errors else '',
        plan_b64=plan_b64,
        sample_items=plan_items[:50],
    )


# =========================
#     QUICK ROLE CHANGE
# =========================
@admin_bp.route('/users/<int:user_id>/role', methods=['POST'], endpoint='change_role')
@superadmin_required
def change_role(user_id):
    role = (request.form.get('role') or '').strip()
    u = db.session.get(User, user_id) or abort(404)
    if role not in assignable_roles() or not can_manage(u):
        flash('Эту роль вы назначить не можете', 'danger')
        return _back()
    if u.id == current_user.id:
        flash('Свою роль поменять нельзя', 'warning')
        return _back()
    u.role = role
    db.session.commit()
    flash(f'Роль {u.username}: {role}', 'success')
    return _back()
