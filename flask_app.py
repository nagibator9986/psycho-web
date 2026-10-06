import os
import io
import uuid
from datetime import datetime

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    jsonify,
    send_file,
    abort,
)
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import func, and_

from flask_login import (
    login_user,
    logout_user,
    login_required,
    current_user,
)

from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.pdfbase import pdfmetrics
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table
from reportlab.pdfbase.ttfonts import TTFont

# общий db и login_manager
from extensions import db, login_manager
from models import (
    User,
    Group,
    Post,
    Comment,
    Test,
    Question,
    QuestionOption,
    TestResult,
    TestInterpretation,
    TestAnswer,
    Message,
    Article,
    StudentReport,
    Appointment,
    Meeting,
    MeetingRequest,
    MeetingProtocol,
    TestScaleOption,
)

# =========================
#       APP INIT
# =========================

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///psych_help.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['REPORT_FOLDER'] = 'static/reports'

db.init_app(app)

login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'


@login_manager.user_loader
def load_user(user_id: str):
    try:
        return User.query.get(int(user_id))
    except (TypeError, ValueError):
        return None


with app.app_context():
    db.create_all()

# подключаем админ-панель
from admin import admin_bp  # noqa: E402

app.register_blueprint(admin_bp)

# =========================
#       HELPERS
# =========================

# ====== МНОГОМЕРНЫЕ ШКАЛОВЫЕ ТЕСТЫ (подшкалы) ======
# ПОДСТАВЬ сюда реальный ID теста Олвеуса из БД!
OLWEUS_BULLYING_TEST_ID = 2  # пример, поменяй на фактический id

SCALE_SUBSCALES_CONFIG = {
    # Тест Олвеуса: 4 подсчёта в одном тесте
    OLWEUS_BULLYING_TEST_ID: {
        "Прямой активный буллинг":  {1, 3, 5, 6},
        "Косвенный активный буллинг": {2, 4},
        "Прямой пассивный буллинг": {7, 10, 11, 13},
        "Косвенный пассивный буллинг": {8, 9, 12},
    },
    # сюда можно добавлять другие тесты
}
def _build_question_index_map(test):
    """
    Возвращает {question_id: номер_вопроса} (1, 2, 3, ...).
    Если у Question есть поле order_index — лучше сортировать по нему.
    """
    ordered = list(test.questions)  # сейчас по порядку добавления
    return {q.id: i for i, q in enumerate(ordered, start=1)}


def interpret_scale_multi(test, per_question_scores):
    """
    Универсальная интерпретация многомерного шкалового теста (test_type == 'scale_multi').

    per_question_scores: dict {question_id: score}
    Ожидает, что конфиг подшкал описан в SCALE_SUBSCALES_CONFIG[test.id].

    Возвращает:
      total_score: общая сумма по всем шкалам (можно хранить в TestResult.score)
      result_text: текстовая интерпретация (4 шкалы)
      subscales:   dict {name: {"score": ..., "max": ..., "percent": ..., "level": ...}}
    """
    if test.id not in SCALE_SUBSCALES_CONFIG:
        # если конфиг не задан — считаем как обычный шкальный тест
        total = sum(per_question_scores.values())
        return total, f"Итоговый балл: {total}.", {}

    groups = SCALE_SUBSCALES_CONFIG[test.id]
    q_index = _build_question_index_map(test)

    # максимальный балл по вопросу
    max_score_per_question = {}
    for q in test.questions:
        if not q.options:
            continue
        max_score_per_question[q.id] = max((opt.score or 0) for opt in q.options)

    group_scores = {name: 0 for name in groups}
    group_max = {name: 0 for name in groups}

    for q in test.questions:
        q_num = q_index.get(q.id)
        if q_num is None:
            continue

        score = per_question_scores.get(q.id, 0)
        max_q = max_score_per_question.get(q.id, 0)

        for group_name, nums in groups.items():
            if q_num in nums:
                group_scores[group_name] += score
                group_max[group_name] += max_q

    def level_by_percent(p):
        if p < 25:
            return "низкий уровень проявлений"
        elif p < 50:
            return "умеренный уровень проявлений"
        elif p < 75:
            return "повышенный уровень проявлений"
        else:
            return "высокий уровень проявлений"

    lines = []
    total_score = 0
    subscale_details = {}

    for name in groups:
        s = group_scores[name]
        m = group_max[name] or 1
        total_score += s
        pct = round(s * 100 / m, 1)
        lvl = level_by_percent(pct)

        lines.append(f"{name}: {s} из {m} баллов ({pct}%) — {lvl}.")
        subscale_details[name] = {
            "score": s,
            "max": m,
            "percent": pct,
            "level": lvl,
        }

    result_text = (
        "Профиль по шкалам:\n\n"
        + "\n".join(lines)
        + "\n\nЧем выше показатель по шкале, тем более выражен соответствующий аспект."
    )

    return total_score, result_text, subscale_details

def ensure_group(name: str, course: int | None = None):
    """Вернёт существующую группу по имени или создаст новую."""
    if not name:
        return None
    g = Group.query.filter_by(name=name).first()
    if not g:
        g = Group(name=name, course=course or 1)
        db.session.add(g)
        db.session.flush()
    else:
        if course and g.course != course:
            g.course = course
            db.session.flush()
    return g


def is_psychologist() -> bool:
    return current_user.is_authenticated and current_user.role == 'psychologist'


def is_student() -> bool:
    return current_user.is_authenticated and current_user.role == 'student'


def get_current_user():
    return current_user if current_user.is_authenticated else None


def test_has_kazakh(test: Test) -> bool:
    """Есть ли у теста/вопросов/ответов казахский текст."""
    if getattr(test, 'title_kk', None) or getattr(test, 'description_kk', None):
        return True
    for q in test.questions:
        if getattr(q, 'text_kk', None):
            return True
        for opt in q.options:
            if getattr(opt, 'text_kk', None):
                return True
    return False


app.jinja_env.globals.update(
    get_current_user=get_current_user,
    is_psychologist=is_psychologist,
    is_student=is_student,
    TestScaleOption=TestScaleOption,  # <--- добавили класс в глобалы Jinja
)


# =========================
#   PDF HELPERS
# =========================


def generate_pdf_report(report: StudentReport):
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()

    font_path = (
        "C:/Windows/Fonts/Arial.ttf"
        if os.name == 'nt'
        else "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"
    )
    pdfmetrics.registerFont(TTFont('Arial', font_path))
    styles['Title'].fontName = 'Arial'
    styles['Normal'].fontName = 'Arial'
    styles['BodyText'].fontName = 'Arial'

    elements = []
    student_name = (
        report.student.full_name
        if report.student and report.student.full_name
        else "Неизвестный студент"
    )
    elements.append(Paragraph(f"Отчёт о студенте: {student_name}", styles['Title']))
    elements.append(Spacer(1, 12))

    psychologist = User.query.get(report.psychologist_id)
    psychologist_name = (
        psychologist.full_name if psychologist and psychologist.full_name else "Неизвестный психолог"
    )

    created_at_str = (
        report.created_at.strftime('%d.%m.%Y %H:%M') if report.created_at else "Дата не указана"
    )

    data = [
        ["Параметр", "Описание"],
        ["Дата создания", created_at_str],
        ["Психолог", psychologist_name],
        ["Учебная успеваемость", report.academic_performance or "Не указано"],
        ["Эмоциональное состояние", report.emotional_state or "Не указано"],
        ["Социальное взаимодействие", report.social_interaction or "Не указано"],
        ["Уровень стресса", report.stress_level or "Не указано"],
        ["Качество сна", report.sleep_quality or "Не указано"],
        ["Мотивация", report.motivation or "Не указано"],
        ["Поведенческие паттерны", report.behavior_patterns or "Не указано"],
        ["Рекомендации", report.recommendations or "Не указано"],
        ["Дополнительные заметки", report.additional_notes or "Не указано"],
    ]

    table = Table(data, colWidths=[150, 400])
    table.setStyle(
        [
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, -1), 'Arial'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('BACKGROUND', (0, 1), (-1, -1), colors.white),
        ]
    )
    elements.append(table)

    doc.build(elements)
    buffer.seek(0)
    return buffer


def generate_protocol_pdf(protocol: MeetingProtocol):
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()
    font_path = (
        "C:/Windows/Fonts/Arial.ttf"
        if os.name == 'nt'
        else "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"
    )
    pdfmetrics.registerFont(TTFont('Arial', font_path))
    styles['Title'].fontName = 'Arial'
    styles['Normal'].fontName = 'Arial'
    styles['BodyText'].fontName = 'Arial'

    elements = []
    student_name = (
        protocol.student.full_name
        if protocol.student and protocol.student.full_name
        else "Неизвестный студент"
    )
    elements.append(Paragraph(f"Протокол встречи: {student_name}", styles['Title']))
    elements.append(Spacer(1, 12))

    psychologist = User.query.get(protocol.psychologist_id)
    psychologist_name = (
        psychologist.full_name if psychologist and psychologist.full_name else "Неизвестный психолог"
    )

    session_date_str = (
        protocol.session_date.strftime('%d.%m.%Y %H:%M')
        if protocol.session_date
        else "Дата не указана"
    )

    data = [
        ["Параметр", "Описание"],
        ["Дата встречи", session_date_str],
        ["Психолог", psychologist_name],
        ["Продолжительность (мин)", str(protocol.duration or "Не указано")],
        ["Обсуждаемые темы", protocol.topics_discussed or "Не указано"],
        ["Эмоциональное состояние", protocol.emotional_state or "Не указано"],
        ["Заметки о прогрессе", protocol.progress_notes or "Не указано"],
        ["Рекомендации", protocol.recommendations or "Не указано"],
        ["Домашнее задание", protocol.homework or "Не указано"],
        ["Дополнительные комментарии", protocol.additional_comments or "Не указано"],
    ]

    table = Table(data, colWidths=[150, 400])
    table.setStyle(
        [
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, -1), 'Arial'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('BACKGROUND', (0, 1), (-1, -1), colors.white),
        ]
    )
    elements.append(table)

    doc.build(elements)
    buffer.seek(0)
    return buffer


def get_cyr_styles_simple():
    font_path = os.path.join(app.root_path, "DejaVuSans.ttf")
    if os.path.exists(font_path):
        pdfmetrics.registerFont(TTFont("DejaVuSans", font_path))
        base = getSampleStyleSheet()
        H = ParagraphStyle('H', parent=base['Heading3'], fontName='DejaVuSans')
        T = ParagraphStyle('T', parent=base['Title'], fontName='DejaVuSans')
        P = ParagraphStyle('P', parent=base['BodyText'], fontName='DejaVuSans')
        return T, H, P
    # fallback
    base = getSampleStyleSheet()
    return base['Title'], base['Heading3'], base['BodyText']


def generate_test_results_pdf(test: Test):
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    T, H, P = get_cyr_styles_simple()
    elements = []
    elements.append(Paragraph(f"Результаты теста: {test.title}", T))
    elements.append(Spacer(1, 12))

    from sqlalchemy import asc

    rows = (
        db.session.query(
            User.full_name,
            User.username,
            TestResult.score,
            TestResult.result_text,
            Group.name,
        )
        .join(TestResult, TestResult.user_id == User.id)
        .outerjoin(Group, User.group_id == Group.id)
        .filter(TestResult.test_id == test.id)
        .order_by(asc(Group.name), asc(User.full_name), asc(User.username))
        .all()
    )

    grouped: dict[str, list[tuple[str, str, int, str]]] = {}
    for full_name, username, score, interp_text, group_name in rows:
        gname = group_name or "Без группы"
        grouped.setdefault(gname, []).append(
            (
                full_name or "—",
                username or "—",
                score if score is not None else 0,
                interp_text or "—",
            )
        )

    for gname, items in grouped.items():
        elements.append(Paragraph(f"Группа: {gname}", H))
        elements.append(Spacer(1, 6))
        data = [["ФИО", "Логин", "Баллы", "Интерпретация"]]
        for full_name, username, score, interp_text in items:
            data.append([full_name, username, str(score), interp_text])
        table = Table(data, colWidths=[170, 120, 60, 230])
        table.setStyle(
            [
                ('FONTNAME', (0, 0), (-1, -1), 'DejaVuSans'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('BACKGROUND', (0, 1), (-1, -1), colors.white),
            ]
        )
        elements.append(table)
        elements.append(Spacer(1, 12))

    doc.build(elements)
    buffer.seek(0)
    return buffer

# ====== МНОГОМЕРНЫЕ ШКАЛОВЫЕ ТЕСТЫ (подшкалы) ======
# ПОДСТАВЬ сюда реальный ID теста Олвеуса из БД!
OLWEUS_BULLYING_TEST_ID = 2  # пример, поменяй на фактический id

SCALE_SUBSCALES_CONFIG = {
    # Тест Олвеуса: 4 подсчёта в одном тесте
    OLWEUS_BULLYING_TEST_ID: {
        "Прямой активный буллинг":  {1, 3, 5, 6},
        "Косвенный активный буллинг": {2, 4},
        "Прямой пассивный буллинг": {7, 10, 11, 13},
        "Косвенный пассивный буллинг": {8, 9, 12},
    },
    # сюда можно добавлять другие тесты
}

# =========================
#         ROUTES
# =========================


@app.route('/')
def index():
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


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = (request.form.get('username') or '').strip()
        email = (request.form.get('email') or '').strip().lower()
        password = (request.form.get('password') or '').strip()
        full_name = (request.form.get('full_name') or '').strip()
        group_id = request.form.get('group_id')

        if not all([username, email, password, full_name, group_id]):
            flash('Заполните все поля: ИИН, ФИО, email, пароль и группу', 'danger')
            return redirect(url_for('register'))

        if User.query.filter_by(username=username).first():
            flash('Это имя пользователя (ИИН) уже занято', 'danger')
            return redirect(url_for('register'))
        if User.query.filter_by(email=email).first():
            flash('Этот email уже используется', 'danger')
            return redirect(url_for('register'))

        try:
            gid = int(group_id)
        except Exception:
            flash('Неверная группа', 'danger')
            return redirect(url_for('register'))

        grp = Group.query.get(gid)
        if not grp:
            flash('Выбранная группа не найдена', 'danger')
            return redirect(url_for('register'))

        new_user = User(
            username=username,
            email=email,
            password=generate_password_hash(password),
            role='student',
            full_name=full_name,
            group_id=grp.id,
        )
        db.session.add(new_user)
        db.session.commit()

        flash('Регистрация прошла успешно! Теперь вы можете войти.', 'success')
        return redirect(url_for('login'))

    all_groups = Group.query.order_by(Group.course.asc(), Group.name.asc()).all()
    return render_template('register.html', groups=all_groups)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = (request.form.get('username') or '').strip()
        password = (request.form.get('password') or '').strip()

        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            login_user(user)  # <--- ВАЖНО
            flash('Вы успешно вошли в систему!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Неверное имя пользователя или пароль', 'danger')

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()  # <--- ВАЖНО
    flash('Вы вышли из системы', 'info')
    return redirect(url_for('index'))


# ---------- DASHBOARD & PROFILE ----------


@app.route('/dashboard')
@login_required
def dashboard():
    user = current_user

    if user.role == 'psychologist':
        tests = (
            Test.query.filter_by(user_id=user.id)
            .order_by(Test.created_at.desc())
            .limit(5)
            .all()
        )
        posts = (
            Post.query.filter_by(user_id=user.id)
            .order_by(Post.created_at.desc())
            .limit(5)
            .all()
        )
        unread_messages = Message.query.filter_by(
            recipient_id=user.id, is_read=False
        ).count()
        students_count = User.query.filter_by(role='student').count()
        pending_appointments = Appointment.query.filter_by(
            psychologist_id=user.id, status='pending'
        ).count()
        upcoming_meetings = (
            Meeting.query.filter_by(psychologist_id=user.id, status='planned')
            .order_by(Meeting.scheduled_at.asc())
            .limit(5)
            .all()
        )
        past_meetings = (
            Meeting.query.filter_by(psychologist_id=user.id, status='completed')
            .order_by(Meeting.scheduled_at.desc())
            .limit(5)
            .all()
        )

        return render_template(
            'psychologist_dashboard.html',
            user=user,
            tests=tests,
            posts=posts,
            unread_messages=unread_messages,
            students_count=students_count,
            pending_appointments=pending_appointments,
            upcoming_meetings=upcoming_meetings,
            past_meetings=past_meetings,
        )

    else:
        available_tests = (
            Test.query.filter_by(is_active=True)
            .order_by(func.random())
            .limit(3)
            .all()
        )
        recent_results = (
            TestResult.query.filter_by(user_id=user.id)
            .order_by(TestResult.created_at.desc())
            .limit(3)
            .all()
        )
        unread_messages = Message.query.filter_by(
            recipient_id=user.id, is_read=False
        ).count()
        upcoming_appointments = (
            Appointment.query.filter_by(student_id=user.id, status='confirmed')
            .order_by(Appointment.appointment_date.asc())
            .limit(3)
            .all()
        )
        return render_template(
            'student_dashboard.html',
            user=user,
            available_tests=available_tests,
            recent_results=recent_results,
            unread_messages=unread_messages,
            upcoming_appointments=upcoming_appointments,
        )


@app.route('/profile/<username>')
@login_required
def profile(username):
    user = User.query.filter_by(username=username).first_or_404()
    posts = (
        Post.query.filter_by(user_id=user.id)
        .order_by(Post.created_at.desc())
        .limit(5)
        .all()
    )
    can_edit = current_user.id == user.id
    return render_template('profile.html', user=user, posts=posts, can_edit=can_edit)


@app.route('/profile/edit', methods=['GET', 'POST'])
@login_required
def edit_profile():
    user = current_user
    if request.method == 'POST':
        user.full_name = request.form.get('full_name', user.full_name)
        user.bio = request.form.get('bio', user.bio)

        if 'profile_pic' in request.files:
            file = request.files['profile_pic']
            if file.filename:
                filename = str(uuid.uuid4()) + os.path.splitext(file.filename)[1]
                os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                user.profile_pic = filename

        db.session.commit()
        flash('Профиль успешно обновлён', 'success')
        return redirect(url_for('profile', username=user.username))
    return render_template('edit_profile.html', user=user)


# ---------- TESTS ----------


@app.route('/tests')
@login_required
def tests():
    user = current_user
    if user.role == 'psychologist':
        tests = (
            Test.query.filter_by(user_id=user.id)
            .order_by(Test.created_at.desc())
            .all()
        )
        total_students = User.query.filter_by(role='student').count()
        total_results = (
            TestResult.query.join(Test)
            .filter(Test.user_id == user.id)
            .count()
        )
        return render_template(
            'psychologist_tests.html',
            tests=tests,
            total_students=total_students,
            total_results=total_results,
        )
    else:
        available_tests = (
            Test.query.filter_by(is_active=True)
            .order_by(Test.created_at.desc())
            .all()
        )
        completed_ids = {
            r.test_id
            for r in TestResult.query.filter_by(user_id=user.id).all()
        }
        return render_template(
            'student_tests.html',
            tests=available_tests,
            completed_test_ids=completed_ids,
        )


@app.route('/tests/create', methods=['GET', 'POST'])
@login_required
def create_test():
    if not is_psychologist():
        abort(403)

    if request.method == 'POST':
        title_ru = (request.form.get('title') or '').strip()
        title_kk = (request.form.get('title_kk') or '').strip()
        description_ru = (request.form.get('description') or '').strip()
        description_kk = (request.form.get('description_kk') or '').strip()
        test_type = request.form.get('test_type', 'classic')

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
        )
        db.session.add(test)
        db.session.flush()  # нужен test.id

        if test_type == 'scale':
            default_scale = [
                ('Всегда', 'Әрқашан', 4),
                ('Часто', 'Жиі', 3),
                ('Иногда', 'Кейде', 2),
                ('Никогда', 'Ешқашан', 1),
            ]
            for i, (ru, kk, score) in enumerate(default_scale):
                db.session.add(
                    TestScaleOption(
                        test_id=test.id,
                        order_index=i,
                        label_ru=ru,
                        label_kk=kk,
                        score=score,
                    )
                )

        db.session.commit()
        flash('Тест создан. Теперь добавьте вопросы.', 'success')
        return redirect(url_for('add_questions', test_id=test.id))

    return render_template('create_test.html')


@app.route('/tests/<int:test_id>/questions', methods=['GET', 'POST'])
@login_required
def add_questions(test_id):
    test = Test.query.get_or_404(test_id)
    if not is_psychologist() or test.user_id != current_user.id:
        abort(403)

    # Удаление вопроса
    if request.method == 'POST' and 'delete_question' in request.form:
        q_id = int(request.form['delete_question'])
        q = Question.query.get_or_404(q_id)
        if q.test_id != test.id:
            abort(403)
        TestAnswer.query.filter_by(question_id=q.id).delete()
        QuestionOption.query.filter_by(question_id=q.id).delete()
        db.session.delete(q)
        db.session.commit()
        flash('Вопрос удалён', 'success')
        return redirect(url_for('add_questions', test_id=test.id))

    # Добавление нового вопроса
    if request.method == 'POST' and 'text_ru' in request.form:
        text_ru = (request.form.get('text_ru') or '').strip()
        text_kk = (request.form.get('text_kk') or '').strip()

        if not text_ru and not text_kk:
            flash('Введите текст вопроса хотя бы на одном языке', 'danger')
            return redirect(url_for('add_questions', test_id=test.id))

        if test.test_type == 'classic':
            question_type = request.form.get('question_type')
            if question_type not in ('text', 'single_choice', 'multiple_choice', 'scale_choice'):
                flash('Выберите тип вопроса', 'danger')
                return redirect(url_for('add_questions', test_id=test.id))
        else:
            # шкальная методика: один вариант ответа
            question_type = 'single_choice'

        question = Question(
            test_id=test.id,
            text=text_ru or text_kk,
            text_kk=text_kk or None,
            question_type=question_type,
        )
        db.session.add(question)
        db.session.flush()

        if test.test_type == 'classic' and question_type != 'text':
            texts_ru = request.form.getlist('option_text_ru[]')
            texts_kk = request.form.getlist('option_text_kk[]')
            scores = request.form.getlist('option_score[]')

            for ru, kk, score in zip(texts_ru, texts_kk, scores):
                ru = (ru or '').strip()
                kk = (kk or '').strip()
                if not ru and not kk:
                    continue
                try:
                    score_val = int(score)
                except (TypeError, ValueError):
                    score_val = 0
                db.session.add(
                    QuestionOption(
                        question_id=question.id,
                        text=ru or kk,
                        text_kk=kk or None,
                        score=score_val,
                    )
                )

        elif test.test_type == 'scale':
            scale_opts = TestScaleOption.query.filter_by(test_id=test.id).order_by(
                TestScaleOption.order_index
            ).all()
            if not scale_opts:
                flash('Сначала задайте шкальные варианты для теста', 'danger')
                db.session.rollback()
                return redirect(url_for('add_questions', test_id=test.id))

            for so in scale_opts:
                db.session.add(
                    QuestionOption(
                        question_id=question.id,
                        text=so.label_ru,
                        text_kk=so.label_kk,
                        score=so.score,
                    )
                )

        db.session.commit()
        flash('Вопрос добавлен', 'success')
        return redirect(url_for('add_questions', test_id=test.id))

    return render_template('add_questions.html', test=test)


@app.route('/tests/<int:test_id>/scale-options', methods=['POST'])
@login_required
def update_scale_options(test_id):
    test = Test.query.get_or_404(test_id)
    if not is_psychologist() or test.user_id != current_user.id:
        abort(403)
    if test.test_type != 'scale':
        abort(400)

    # простая логика: очищаем и создаём заново
    TestScaleOption.query.filter_by(test_id=test.id).delete()

    labels_ru = request.form.getlist('scale_label_ru[]')
    labels_kk = request.form.getlist('scale_label_kk[]')
    scores = request.form.getlist('scale_score[]')

    order_index = 0
    for ru, kk, score in zip(labels_ru, labels_kk, scores):
        ru = (ru or '').strip()
        kk = (kk or '').strip()
        if not ru and not kk:
            continue
        try:
            score_val = int(score)
        except (TypeError, ValueError):
            score_val = 0
        db.session.add(
            TestScaleOption(
                test_id=test.id,
                order_index=order_index,
                label_ru=ru or kk,
                label_kk=kk or None,
                score=score_val,
            )
        )
        order_index += 1

    db.session.commit()
    flash('Шкаловые варианты обновлены', 'success')
    return redirect(url_for('add_questions', test_id=test.id))


@app.route('/tests/<int:test_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_test(test_id):
    if not is_psychologist():
        return redirect(url_for('login'))

    test = Test.query.get_or_404(test_id)
    if test.user_id != current_user.id:
        flash('У вас нет прав для редактирования этого теста', 'danger')
        return redirect(url_for('tests'))

    if request.method == 'POST':
        test.title = request.form.get('title', test.title)
        test.description = request.form.get('description', test.description)
        test.is_active = 'is_active' in request.form
        db.session.commit()
        flash('Тест обновлён', 'success')
        return redirect(url_for('tests'))
    return render_template('edit_test.html', test=test)


@app.route('/tests/<int:test_id>/delete', methods=['POST'])
@login_required
def delete_test(test_id):
    if not is_psychologist():
        return redirect(url_for('login'))

    test = Test.query.get_or_404(test_id)
    if test.user_id != current_user.id:
        flash('У вас нет прав для удаления этого теста', 'danger')
        return redirect(url_for('tests'))

    db.session.delete(test)
    db.session.commit()
    flash('Тест удалён', 'success')
    return redirect(url_for('tests'))


@app.route('/tests/<int:test_id>/download_results')
@login_required
def download_test_results(test_id):
    if not is_psychologist():
        return redirect(url_for('login'))

    test = Test.query.get_or_404(test_id)
    if test.user_id != current_user.id:
        flash('У вас нет прав на выгрузку этого теста', 'danger')
        return redirect(url_for('tests'))

    pdf_buffer = generate_test_results_pdf(test)
    filename = f"test_results_{test.id}.pdf"
    return send_file(pdf_buffer, as_attachment=True, download_name=filename)


@app.route('/tests/<int:test_id>/add_interpretation', methods=['POST'])
@login_required
def add_interpretation(test_id):
    if not is_psychologist():
        return redirect(url_for('login'))

    test = Test.query.get_or_404(test_id)
    if test.user_id != current_user.id:
        flash('Нет прав для изменения этого теста', 'danger')
        return redirect(url_for('tests'))

    if 'delete_interpretation' in request.form:
        interp = TestInterpretation.query.get_or_404(
            request.form['delete_interpretation']
        )
        db.session.delete(interp)
        db.session.commit()
        flash('Интерпретация удалена', 'info')
        return redirect(url_for('add_questions', test_id=test_id))

    min_score = int(request.form['min_score'])
    max_score = int(request.form['max_score'])
    text = request.form['text']

    interp = TestInterpretation(
        test_id=test_id,
        min_score=min_score,
        max_score=max_score,
        text=text,
    )
    db.session.add(interp)
    db.session.commit()

    flash('Интерпретация добавлена!', 'success')
    return redirect(url_for('add_questions', test_id=test_id))


@app.route('/tests/<int:test_id>/take', methods=['GET', 'POST'])
@login_required
def take_test(test_id):
    test = Test.query.get_or_404(test_id)
    if not test.is_active:
        abort(403)

    # есть ли казахская версия
    has_kk = any(
        (q.text_kk and q.text_kk.strip())
        for q in test.questions
    ) or bool(test.title_kk)

    # выбор языка
    lang = request.args.get('lang') or request.form.get('lang')
    if request.method == 'GET' and not lang and has_kk:
        return render_template('choose_test_lang.html', test=test)
    if not lang:
        lang = 'ru'

    if request.method == 'POST':
        test_result = TestResult(
            user_id=current_user.id,
            test_id=test.id,
            created_at=datetime.utcnow(),
            language=lang if hasattr(TestResult, 'language') else None
        )
        db.session.add(test_result)
        db.session.flush()

        total_score = 0
        per_question_scores = {}

        for question in test.questions:
            answer_text = None
            option_id = None
            question_score = 0

            field_name = f'answer_{question.id}'

            if question.question_type == 'text':
                answer_text = request.form.get(field_name) or ''

            elif question.question_type in ['single_choice', 'scale_choice']:
                selected = request.form.get(field_name)
                if selected:
                    option_id = int(selected)
                    option = QuestionOption.query.get(option_id)
                    if option:
                        question_score += option.score or 0

            elif question.question_type == 'multiple_choice':
                selected_ids = request.form.getlist(field_name)
                for sid in selected_ids:
                    opt = QuestionOption.query.get(int(sid))
                    if opt:
                        question_score += opt.score or 0

            total_score += question_score
            per_question_scores[question.id] = question_score

            db.session.add(TestAnswer(
                test_result_id=test_result.id,
                question_id=question.id,
                answer_text=answer_text,
                option_id=option_id
            ))

        # ===== интерпретация в зависимости от типа теста =====
        # 1) МНОГОМЕРНЫЙ ШКАЛОВЫЙ (несколько шкал в одном тесте)
        if getattr(test, 'test_type', None) == 'scale_multi':
            total, text, _subscales = interpret_scale_multi(test, per_question_scores)
            test_result.score = total
            test_result.result_text = text

        else:
            # 2) классический / обычный шкальный тест — старая логика
            interp = TestInterpretation.query.filter(
                and_(
                    TestInterpretation.test_id == test.id,
                    TestInterpretation.min_score <= total_score,
                    TestInterpretation.max_score >= total_score
                )
            ).order_by(TestInterpretation.min_score.desc()).first()

            test_result.score = total_score

            if interp:
                test_result.result_text = interp.text
            else:
                # запасной вариант, если не заданы интерпретации
                if total_score < 20:
                    test_result.result_text = "Низкий уровень. Рекомендуется консультация психолога."
                elif 20 <= total_score < 40:
                    test_result.result_text = "Средний уровень. Есть некоторые проблемы, но в целом ситуация под контролем."
                else:
                    test_result.result_text = "Высокий уровень. Ваше психологическое состояние в норме."

        db.session.commit()
        return redirect(url_for('test_result', result_id=test_result.id))

    return render_template('take_test.html', test=test, lang=lang, has_kk=has_kk)



@app.route('/test_result/<int:result_id>')
@login_required
def test_result(result_id):
    result = TestResult.query.get_or_404(result_id)

    # студент видит только свои результаты
    if is_student() and result.user_id != current_user.id:
        flash('У вас нет прав для просмотра этого результата', 'danger')
        return redirect(url_for('tests'))

    # психолог может видеть результаты по своим тестам
    if is_psychologist() and result.test.user_id != current_user.id:
        flash('У вас нет прав для просмотра этого результата', 'danger')
        return redirect(url_for('tests'))

    return render_template('test_result.html', result=result)


# ---------- ANALYTICS & REPORTS ----------


@app.route('/analytics/students')
@login_required
def student_list():
    if not is_psychologist():
        return redirect(url_for('login'))
    students = (
        User.query.filter_by(role='student')
        .order_by(User.created_at.desc())
        .all()
    )
    return render_template('student_list.html', students=students)


@app.route('/analytics/students/<int:student_id>')
@login_required
def student_analytics(student_id):
    if not is_psychologist():
        return redirect(url_for('login'))

    student = User.query.get_or_404(student_id)
    if student.role != 'student':
        flash('Это не студент', 'danger')
        return redirect(url_for('student_list'))

    test_results = (
        TestResult.query.filter_by(user_id=student_id)
        .order_by(TestResult.created_at.asc())
        .all()
    )
    total_tests = len(test_results)
    avg_score = (
        db.session.query(func.avg(TestResult.score))
        .filter_by(user_id=student_id)
        .scalar()
        or 0
    )
    last_test = test_results[-1] if test_results else None
    scores_over_time = [(r.created_at, r.score) for r in test_results]
    messages_sent = Message.query.filter_by(sender_id=student_id).count()
    posts_count = Post.query.filter_by(user_id=student_id).count()
    reports = (
        StudentReport.query.filter_by(student_id=student_id)
        .order_by(StudentReport.created_at.desc())
        .all()
    )
    protocols = (
        MeetingProtocol.query.filter_by(student_id=student_id)
        .order_by(MeetingProtocol.created_at.desc())
        .all()
    )

    return render_template(
        'student_analytics.html',
        student=student,
        total_tests=total_tests,
        avg_score=avg_score,
        last_test=last_test,
        scores_over_time=scores_over_time,
        messages_sent=messages_sent,
        posts_count=posts_count,
        reports=reports,
        protocols=protocols,
    )


@app.route('/analytics/students/<int:student_id>/report', methods=['GET', 'POST'])
@login_required
def create_report(student_id):
    if not is_psychologist():
        return redirect(url_for('login'))

    student = User.query.get_or_404(student_id)
    if student.role != 'student':
        flash('Это не студент', 'danger')
        return redirect(url_for('student_list'))

    if request.method == 'POST':
        report = StudentReport(
            student_id=student_id,
            psychologist_id=current_user.id,
            created_at=datetime.utcnow(),
            academic_performance=request.form.get('academic_performance'),
            emotional_state=request.form.get('emotional_state'),
            social_interaction=request.form.get('social_interaction'),
            stress_level=request.form.get('stress_level'),
            sleep_quality=request.form.get('sleep_quality'),
            motivation=request.form.get('motivation'),
            behavior_patterns=request.form.get('behavior_patterns'),
            recommendations=request.form.get('recommendations'),
            additional_notes=request.form.get('additional_notes'),
        )

        pdf_buffer = generate_pdf_report(report)
        filename = f"report_{student_id}_{uuid.uuid4().hex}.pdf"
        filepath = os.path.join(app.config['REPORT_FOLDER'], filename)
        os.makedirs(app.config['REPORT_FOLDER'], exist_ok=True)
        with open(filepath, 'wb') as f:
            f.write(pdf_buffer.getvalue())
        report.pdf_filename = filename

        db.session.add(report)
        db.session.commit()

        flash('Отчёт успешно создан!', 'success')
        return redirect(url_for('student_analytics', student_id=student_id))
    return render_template('create_report.html', student=student)


@app.route(
    '/analytics/students/<int:student_id>/report/<int:report_id>/download'
)
@login_required
def download_report(student_id, report_id):
    if not is_psychologist():
        return redirect(url_for('login'))

    report = StudentReport.query.get_or_404(report_id)
    if report.student_id != student_id or report.psychologist_id != current_user.id:
        flash('У вас нет доступа к этому отчёту', 'danger')
        return redirect(url_for('student_list'))

    filepath = os.path.join(app.config['REPORT_FOLDER'], report.pdf_filename)
    return send_file(
        filepath,
        as_attachment=True,
        download_name=f"report_{report.student.username}_{report.created_at.strftime('%Y%m%d')}.pdf",
    )


# ---------- APPOINTMENTS & MEETINGS ----------


@app.route('/appointments')
@login_required
def appointments():
    user = current_user
    if user.role == 'psychologist':
        appointments = (
            Appointment.query.filter_by(psychologist_id=user.id)
            .order_by(Appointment.appointment_date.asc())
            .all()
        )
        meetings = (
            Meeting.query.filter_by(psychologist_id=user.id)
            .order_by(Meeting.scheduled_at.asc())
            .all()
        )
        protocols = (
            MeetingProtocol.query.filter_by(psychologist_id=user.id)
            .order_by(MeetingProtocol.session_date.desc())
            .all()
        )
    else:
        appointments = (
            Appointment.query.filter_by(student_id=user.id)
            .order_by(Appointment.appointment_date.asc())
            .all()
        )
        meetings = (
            Meeting.query.filter_by(student_id=user.id)
            .order_by(Meeting.scheduled_at.asc())
            .all()
        )
        protocols = (
            MeetingProtocol.query.filter_by(student_id=user.id)
            .order_by(MeetingProtocol.session_date.desc())
            .all()
        )
    return render_template(
        'appointments.html',
        appointments=appointments,
        meetings=meetings,
        protocols=protocols,
    )


@app.route('/appointments/create/<int:student_id>', methods=['GET', 'POST'])
@login_required
def create_appointment(student_id):
    if not is_psychologist():
        return redirect(url_for('login'))

    student = User.query.get_or_404(student_id)
    if student.role != 'student':
        flash('Это не студент', 'danger')
        return redirect(url_for('appointments'))

    if request.method == 'POST':
        appointment_date = datetime.strptime(
            request.form['appointment_date'], '%Y-%m-%dT%H:%M'
        )
        purpose = request.form.get('purpose')

        exists_a = Appointment.query.filter_by(
            student_id=student_id,
            psychologist_id=current_user.id,
            appointment_date=appointment_date,
        ).first()
        if exists_a:
            flash('Такая встреча уже существует для указанного времени.', 'info')
            return redirect(url_for('appointments'))

        exists_m = Meeting.query.filter_by(
            student_id=student_id,
            psychologist_id=current_user.id,
            scheduled_at=appointment_date,
        ).first()

        appointment = Appointment(
            student_id=student_id,
            psychologist_id=current_user.id,
            appointment_date=appointment_date,
            purpose=purpose,
        )
        db.session.add(appointment)

        if not exists_m:
            meeting = Meeting(
                student_id=student_id,
                psychologist_id=current_user.id,
                scheduled_at=appointment_date,
                status='planned',
            )
            db.session.add(meeting)

        message = Message(
            content=(
                f"Назначена встреча на {appointment_date.strftime('%d.%m.%Y %H:%M')}. "
                f"Цель: {purpose or 'Не указана'}"
            ),
            sender_id=current_user.id,
            recipient_id=student_id,
            is_anonymous=False,
        )
        db.session.add(message)
        db.session.commit()

        flash('Встреча успешно назначена!', 'success')
        return redirect(url_for('appointments'))
    return render_template('create_appointment.html', student=student)


@app.route('/appointments/<int:appointment_id>/update', methods=['POST'])
@login_required
def update_appointment(appointment_id):
    appointment = Appointment.query.get_or_404(appointment_id)

    if is_psychologist() and appointment.psychologist_id != current_user.id:
        flash('У вас нет прав для изменения этой встречи', 'danger')
        return redirect(url_for('appointments'))

    if is_student() and appointment.student_id != current_user.id:
        flash('У вас нет прав для изменения этой встречи', 'danger')
        return redirect(url_for('appointments'))

    status = request.form.get('status')
    if status in ['confirmed', 'cancelled']:
        appointment.status = status
        meeting = Meeting.query.filter_by(
            student_id=appointment.student_id,
            psychologist_id=appointment.psychologist_id,
            scheduled_at=appointment.appointment_date,
        ).first()
        if meeting:
            if status == 'confirmed' and meeting.scheduled_at <= datetime.utcnow():
                meeting.status = 'completed'
            else:
                meeting.status = status

        db.session.commit()

        recipient_id = (
            appointment.student_id if is_psychologist() else appointment.psychologist_id
        )
        message_content = (
            f"Статус встречи на {appointment.appointment_date.strftime('%d.%m.%Y %H:%M')} "
            f"изменён на: {status}"
        )
        message = Message(
            content=message_content,
            sender_id=current_user.id,
            recipient_id=recipient_id,
            is_anonymous=False,
        )
        db.session.add(message)
        db.session.commit()

        flash(f'Статус встречи обновлён на "{status}"', 'success')
    return redirect(url_for('appointments'))


@app.route('/meetings/<int:meeting_id>/create_protocol', methods=['GET', 'POST'])
@login_required
def create_protocol(meeting_id):
    if not is_psychologist():
        return redirect(url_for('login'))

    meeting = Meeting.query.get_or_404(meeting_id)
    if meeting.psychologist_id != current_user.id:
        flash('У вас нет прав для создания протокола этой встречи', 'danger')
        return redirect(url_for('appointments'))

    if request.method == 'POST':
        protocol = MeetingProtocol(
            meeting_id=meeting_id,
            student_id=meeting.student_id,
            psychologist_id=current_user.id,
            session_date=meeting.scheduled_at,
            duration=request.form.get('duration', type=int),
            topics_discussed=request.form.get('topics_discussed'),
            emotional_state=request.form.get('emotional_state'),
            progress_notes=request.form.get('progress_notes'),
            recommendations=request.form.get('recommendations'),
            homework=request.form.get('homework'),
            additional_comments=request.form.get('additional_comments'),
            created_at=datetime.utcnow(),
        )

        pdf_buffer = generate_protocol_pdf(protocol)
        filename = f"protocol_{meeting_id}_{uuid.uuid4().hex}.pdf"
        filepath = os.path.join(app.config['REPORT_FOLDER'], filename)
        os.makedirs(app.config['REPORT_FOLDER'], exist_ok=True)
        with open(filepath, 'wb') as f:
            f.write(pdf_buffer.getvalue())
        protocol.pdf_filename = filename

        db.session.add(protocol)
        db.session.commit()

        flash('Протокол встречи успешно создан!', 'success')
        return redirect(url_for('appointments'))
    return render_template('create_protocol.html', meeting=meeting)


@app.route('/protocols/<int:protocol_id>/download')
@login_required
def download_protocol(protocol_id):
    if not is_psychologist():
        return redirect(url_for('login'))

    protocol = MeetingProtocol.query.get_or_404(protocol_id)
    if protocol.psychologist_id != current_user.id:
        flash('У вас нет доступа к этому протоколу', 'danger')
        return redirect(url_for('appointments'))

    filepath = os.path.join(app.config['REPORT_FOLDER'], protocol.pdf_filename)
    return send_file(
        filepath,
        as_attachment=True,
        download_name=f"protocol_{protocol.student.username}_{protocol.session_date.strftime('%Y%m%d')}.pdf",
    )


# ---------- POSTS & COMMENTS ----------


@app.route('/posts')
def posts():
    posts = Post.query.order_by(Post.created_at.desc()).all()
    psychologists = (
        User.query.filter_by(role='psychologist')
        .order_by(func.random())
        .limit(5)
        .all()
    )
    return render_template('posts.html', posts=posts, psychologists=psychologists)


@app.route('/posts/create', methods=['GET', 'POST'])
@login_required
def create_post():
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        post = Post(title=title, content=content, user_id=current_user.id)
        db.session.add(post)
        db.session.commit()
        flash('Пост создан!', 'success')
        return redirect(url_for('posts'))
    return render_template('create_post.html')


@app.route('/posts/<int:post_id>')
def view_post(post_id):
    post = Post.query.get_or_404(post_id)
    return render_template('view_post.html', post=post)


@app.route('/posts/<int:post_id>/comment', methods=['POST'])
@login_required
def add_comment(post_id):
    post = Post.query.get_or_404(post_id)
    content = request.form['content']
    is_anonymous = 'is_anonymous' in request.form

    comment = Comment(
        content=content,
        user_id=current_user.id,
        post_id=post_id,
        is_anonymous=is_anonymous,
    )
    db.session.add(comment)
    db.session.commit()
    flash('Комментарий добавлен!', 'success')
    return redirect(url_for('view_post', post_id=post_id))


# ---------- MESSAGES ----------


@app.route('/messages')
@login_required
def messages():
    user = current_user
    if user.role == 'student':
        contacts = User.query.filter_by(role='psychologist').all()
    else:
        contacts = User.query.filter_by(role='student').all()

    conversations = []
    for contact in contacts:
        last_message = (
            Message.query.filter(
                ((Message.sender_id == user.id) & (Message.recipient_id == contact.id))
                | ((Message.sender_id == contact.id) & (Message.recipient_id == user.id))
            )
            .order_by(Message.created_at.desc())
            .first()
        )

        if last_message:
            unread_count = Message.query.filter_by(
                sender_id=contact.id, recipient_id=user.id, is_read=False
            ).count()
            conversations.append(
                {
                    'contact': contact,
                    'last_message': last_message,
                    'unread_count': unread_count,
                }
            )

    return render_template('messages.html', conversations=conversations)


@app.route('/messages/<int:contact_id>', methods=['GET', 'POST'])
@login_required
def chat(contact_id):
    user = current_user
    contact = User.query.get_or_404(contact_id)

    if (user.role == 'student' and contact.role != 'psychologist') or (
        user.role == 'psychologist' and contact.role != 'student'
    ):
        flash('Вы можете общаться только с пользователями другой роли', 'danger')
        return redirect(url_for('messages'))

    if request.method == 'POST':
        if 'content' in request.form:
            content = request.form['content']
            is_anonymous = 'is_anonymous' in request.form
            message = Message(
                content=content,
                sender_id=user.id,
                recipient_id=contact.id,
                is_anonymous=is_anonymous,
            )
            db.session.add(message)

        elif 'appointment_date' in request.form:
            appointment_date = datetime.strptime(
                request.form['appointment_date'], '%Y-%m-%dT%H:%M'
            )
            purpose = request.form.get('purpose')

            student_id = user.id if is_student() else contact.id
            psychologist_id = user.id if is_psychologist() else contact.id

            exists_a = Appointment.query.filter_by(
                student_id=student_id,
                psychologist_id=psychologist_id,
                appointment_date=appointment_date,
            ).first()
            if exists_a:
                flash(
                    'Такая встреча уже существует для указанного времени.', 'info'
                )
                return redirect(url_for('chat', contact_id=contact_id))

            exists_m = Meeting.query.filter_by(
                student_id=student_id,
                psychologist_id=psychologist_id,
                scheduled_at=appointment_date,
            ).first()

            appointment = Appointment(
                student_id=student_id,
                psychologist_id=psychologist_id,
                appointment_date=appointment_date,
                purpose=purpose,
            )
            db.session.add(appointment)

            if not exists_m:
                meeting = Meeting(
                    student_id=student_id,
                    psychologist_id=psychologist_id,
                    scheduled_at=appointment_date,
                    status='planned',
                )
                db.session.add(meeting)

            message = Message(
                content=(
                    f"Предложена встреча на {appointment_date.strftime('%d.%m.%Y %H:%M')}. "
                    f"Цель: {purpose or 'Не указана'}"
                ),
                sender_id=user.id,
                recipient_id=contact.id,
                is_anonymous=False,
            )
            db.session.add(message)

        Message.query.filter_by(
            sender_id=contact.id, recipient_id=user.id, is_read=False
        ).update({'is_read': True})
        db.session.commit()
        return redirect(url_for('chat', contact_id=contact_id))

    msgs = (
        Message.query.filter(
            ((Message.sender_id == user.id) & (Message.recipient_id == contact.id))
            | ((Message.sender_id == contact.id) & (Message.recipient_id == user.id))
        )
        .order_by(Message.created_at.asc())
        .all()
    )

    Message.query.filter_by(
        sender_id=contact.id, recipient_id=user.id, is_read=False
    ).update({'is_read': True})
    db.session.commit()

    return render_template('chat.html', contact=contact, messages=msgs)


# ---------- ARTICLES ----------


@app.route('/articles')
def articles():
    arts = Article.query.order_by(Article.created_at.desc()).all()
    return render_template('articles.html', articles=arts)


@app.route('/articles/create', methods=['GET', 'POST'])
@login_required
def create_article():
    if not is_psychologist():
        return redirect(url_for('login'))

    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        article = Article(title=title, content=content, user_id=current_user.id)

        if 'image' in request.files:
            file = request.files['image']
            if file.filename:
                filename = str(uuid.uuid4()) + os.path.splitext(file.filename)[1]
                os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                article.image_url = filename

        db.session.add(article)
        db.session.commit()
        flash('Статья создана!', 'success')
        return redirect(url_for('articles'))
    return render_template('create_article.html')


@app.route('/articles/<int:article_id>')
def view_article(article_id):
    article = Article.query.get_or_404(article_id)
    return render_template('view_article.html', article=article)


# ---------- SEARCH / EMERGENCY / API ----------


@app.route('/search')
def search():
    query = request.args.get('q', '').strip()
    if not query:
        return redirect(url_for('index'))

    tests = Test.query.filter(
        Test.is_active.is_(True),
        (Test.title.contains(query))
        | (Test.description.contains(query))
        | (Test.title_kk.contains(query))
        | (Test.description_kk.contains(query)),
    ).all()

    articles = Article.query.filter(
        (Article.title.contains(query)) | (Article.content.contains(query))
    ).all()

    posts = Post.query.filter(
        (Post.title.contains(query)) | (Post.content.contains(query))
    ).all()

    psychologists = User.query.filter(
        User.role == 'psychologist',
        (User.full_name.contains(query)) | (User.bio.contains(query)),
    ).all()

    return render_template(
        'search_results.html',
        query=query,
        tests=tests,
        articles=articles,
        posts=posts,
        psychologists=psychologists,
    )


@app.route('/emergency')
def emergency():
    return render_template('emergency.html')


@app.route('/api/messages/unread_count')
def unread_messages_count():
    if not current_user.is_authenticated:
        return jsonify({'count': 0})
    count = Message.query.filter_by(
        recipient_id=current_user.id, is_read=False
    ).count()
    return jsonify({'count': count})


@app.route('/api/meetings/calendar')
@login_required
def meetings_calendar():
    if not is_psychologist():
        return jsonify({'error': 'Unauthorized'}), 401

    meetings = Meeting.query.filter_by(psychologist_id=current_user.id).all()
    events = [
        {
            'id': meeting.id,
            'title': f"Встреча с {meeting.student.full_name or meeting.student.username}",
            'start': meeting.scheduled_at.isoformat(),
            'status': meeting.status,
            'student_id': meeting.student_id,
        }
        for meeting in meetings
    ]
    return jsonify(events)


# =========================
#        ENTRYPOINT
# =========================

if __name__ == '__main__':
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    os.makedirs(app.config['REPORT_FOLDER'], exist_ok=True)
    app.run(debug=True)
