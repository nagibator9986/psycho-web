from datetime import datetime
from flask_login import UserMixin
from extensions import db
from sqlalchemy.schema import UniqueConstraint

class User(UserMixin, db.Model):
    __tablename__ = 'user'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # student | psychologist | admin | superadmin
    full_name = db.Column(db.String(100))
    bio = db.Column(db.Text)
    profile_pic = db.Column(db.String(100))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    group_id = db.Column(db.Integer, db.ForeignKey('groups.id'))

    # --------- Связи ---------

    # Комментарии к постам (author)
    comments = db.relationship(
        'Comment',
        backref='author',
        lazy=True,
    )

    # Тесты, созданные пользователем (психологом) — creator
    tests = db.relationship(
        'Test',
        backref='creator',
        lazy=True,
    )

    # Результаты тестов, пройденные пользователем (студентом)
    test_results = db.relationship(
        'TestResult',
        backref='user',
        lazy=True,
    )

    # Сообщения
    messages_sent = db.relationship(
        'Message',
        foreign_keys='Message.sender_id',
        backref='sender',
        lazy=True,
    )
    messages_received = db.relationship(
        'Message',
        foreign_keys='Message.recipient_id',
        backref='recipient',
        lazy=True,
    )

    # Отчёты по студенту (student_reports)
    reports = db.relationship(
        'StudentReport',
        foreign_keys='StudentReport.student_id',
        backref='student',
        lazy=True,
    )

    # Назначения (Appointment): студент / психолог
    appointments = db.relationship(
        'Appointment',
        foreign_keys='Appointment.student_id',
        backref='student',          # appointment.student в шаблонах
        lazy=True,
    )
    psychologist_appointments = db.relationship(
        'Appointment',
        foreign_keys='Appointment.psychologist_id',
        backref='psychologist',     # appointment.psychologist в шаблонах
        lazy=True,
    )

    # Протоколы встреч (MeetingProtocol): как студент / как психолог
    meeting_protocols = db.relationship(
        'MeetingProtocol',
        foreign_keys='MeetingProtocol.student_id',
        backref='student',          # protocol.student в шаблонах
        lazy=True,
    )
    psychologist_protocols = db.relationship(
        'MeetingProtocol',
        foreign_keys='MeetingProtocol.psychologist_id',
        backref='psychologist',     # protocol.psychologist в шаблонах
        lazy=True,
    )

    def __repr__(self) -> str:
        return f"<User id={self.id} username={self.username!r} role={self.role!r}>"


class Group(db.Model):
    __tablename__ = 'groups'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    course = db.Column(db.Integer, nullable=False, default=1)

    users = db.relationship('User', backref='group', lazy=True)


# =========================
# Форум: посты и комментарии
# =========================

class Post(db.Model):
    __tablename__ = 'post'

    id = db.Column(db.Integer, primary_key=True)

    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)

    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(
        db.DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
    )

    comments = db.relationship(
        'Comment',
        backref='post',
        lazy=True,
        cascade='all, delete-orphan',
    )

    # author.posts — создаётся через этот backref
    author = db.relationship('User', backref='posts', lazy=True)


class Comment(db.Model):
    __tablename__ = 'comment'

    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)

    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_anonymous = db.Column(db.Boolean, default=False)


# =========================
# Психологические тесты
# =========================

class Test(db.Model):
    __tablename__ = 'test'

    id = db.Column(db.Integer, primary_key=True)

    # Базовые поля (русский вариант)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)

    # Казахский вариант (опционально)
    title_kk = db.Column(db.String(200))        # может быть NULL
    description_kk = db.Column(db.Text)

    # Тип теста:
    #   classic — обычный конструктор (разные типы вопросов, свои варианты ответов)
    #   scale   — методики типа «шкала одиночества» (единый набор шкальных ответов)
    test_type = db.Column(db.String(20), nullable=False, default='classic')

    # Автор теста (психолог)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)

    # Вопросы теста
    questions = db.relationship(
        'Question',
        backref='test',
        lazy=True,
        cascade='all, delete-orphan'
    )

    # Результаты прохождения
    results = db.relationship(
        'TestResult',
        backref='test',
        lazy=True,
        cascade='all, delete-orphan'
    )

    # Диапазоны интерпретаций по баллам
    interpretations = db.relationship(
        'TestInterpretation',
        backref='test',
        lazy=True,
        cascade='all, delete-orphan',
        order_by='TestInterpretation.min_score'
    )

    # Общие шкальные варианты для всего теста (для test_type == 'scale')
    scale_options = db.relationship(
        'TestScaleOption',
        backref='test',
        lazy=True,
        cascade='all, delete-orphan',
        order_by='TestScaleOption.order_index'
    )



class Question(db.Model):
    __tablename__ = 'question'

    id = db.Column(db.Integer, primary_key=True)

    # Текст вопроса (RU/KZ)
    text = db.Column(db.Text, nullable=False)   # RU
    text_kk = db.Column(db.Text)               # KZ

    test_id = db.Column(db.Integer, db.ForeignKey('test.id'), nullable=False)

    # text | single_choice | multiple_choice | scale_choice
    question_type = db.Column(db.String(20), nullable=False)

    options = db.relationship(
        'QuestionOption',
        backref='question',
        lazy=True,
        cascade='all, delete-orphan',
    )

    # Ответы студентов на этот вопрос
    answers = db.relationship(
        'TestAnswer',
        backref='question',
        lazy=True,
        cascade='all, delete-orphan',
    )


class QuestionOption(db.Model):
    __tablename__ = 'question_option'

    id = db.Column(db.Integer, primary_key=True)

    # Текст варианта ответа (RU/KZ)
    text = db.Column(db.String(200), nullable=False)  # RU
    text_kk = db.Column(db.String(200))              # KZ

    question_id = db.Column(db.Integer, db.ForeignKey('question.id'), nullable=False)

    # Баллы за выбор этого варианта
    score = db.Column(db.Integer)


class TestScaleOption(db.Model):
    """
    Общий набор шкальных ответов для теста test_type='scale'.

    Например:
      - Всегда / Әрқашан — 4
      - Часто / Жиі — 3
      - Иногда / Кейде — 2
      - Никогда / Ешқашан — 1
    """
    __tablename__ = 'test_scale_option'

    id = db.Column(db.Integer, primary_key=True)

    test_id = db.Column(db.Integer, db.ForeignKey('test.id'), nullable=False, index=True)

    order_index = db.Column(db.Integer, default=0)  # порядок отображения в шкале

    label_ru = db.Column(db.String(200), nullable=False)
    label_kk = db.Column(db.String(200))

    score = db.Column(db.Integer, nullable=False)


class TestResult(db.Model):
    __tablename__ = 'test_result'

    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    test_id = db.Column(db.Integer, db.ForeignKey('test.id'), nullable=False)

    score = db.Column(db.Integer)
    result_text = db.Column(db.Text)

    # Дополнительно можно хранить, на каком языке студент проходил тест
    # 'ru' | 'kk' | None
    language = db.Column(db.String(5))

    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    answers = db.relationship(
        'TestAnswer',
        backref='test_result',
        lazy=True,
        cascade='all, delete-orphan',
    )


class TestInterpretation(db.Model):
    __tablename__ = 'test_interpretation'

    id = db.Column(db.Integer, primary_key=True)

    test_id = db.Column(db.Integer, db.ForeignKey('test.id'), nullable=False, index=True)

    min_score = db.Column(db.Integer, nullable=False)
    max_score = db.Column(db.Integer, nullable=False)

    # Текст интерпретации (пока только на русском;
    # при желании можно добавить text_kk по аналогии)
    text = db.Column(db.Text, nullable=False)


class TestAnswer(db.Model):
    __tablename__ = 'test_answer'

    id = db.Column(db.Integer, primary_key=True)

    test_result_id = db.Column(db.Integer, db.ForeignKey('test_result.id'), nullable=False)
    question_id = db.Column(db.Integer, db.ForeignKey('question.id'), nullable=False)

    # Для текстовых вопросов
    answer_text = db.Column(db.Text)

    # Для вопросов с вариантами
    option_id = db.Column(db.Integer, db.ForeignKey('question_option.id'))
    option = db.relationship('QuestionOption')


# =========================
# Сообщения и статьи
# =========================

class Message(db.Model):
    __tablename__ = 'message'

    id = db.Column(db.Integer, primary_key=True)

    content = db.Column(db.Text, nullable=False)

    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    is_anonymous = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_read = db.Column(db.Boolean, default=False)


class Article(db.Model):
    __tablename__ = 'article'

    id = db.Column(db.Integer, primary_key=True)

    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)

    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    image_url = db.Column(db.String(200))

    user = db.relationship('User', backref='authored_articles', lazy=True)


# =========================
# Отчёты и встречи
# =========================

class StudentReport(db.Model):
    __tablename__ = 'student_report'

    id = db.Column(db.Integer, primary_key=True)

    student_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    psychologist_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    academic_performance = db.Column(db.Text)
    emotional_state = db.Column(db.Text)
    social_interaction = db.Column(db.Text)
    stress_level = db.Column(db.Text)
    sleep_quality = db.Column(db.Text)
    motivation = db.Column(db.Text)
    behavior_patterns = db.Column(db.Text)
    recommendations = db.Column(db.Text)
    additional_notes = db.Column(db.Text)

    pdf_filename = db.Column(db.String(100))


class Appointment(db.Model):
    __tablename__ = 'appointment'

    id = db.Column(db.Integer, primary_key=True)

    student_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    psychologist_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    appointment_date = db.Column(db.DateTime, nullable=False)
    purpose = db.Column(db.Text)

    status = db.Column(db.String(20), default='pending')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    __table_args__ = (
        UniqueConstraint(
            'student_id',
            'psychologist_id',
            'appointment_date',
            name='uq_appointment_unique_slot',
        ),
    )


class Meeting(db.Model):
    __tablename__ = 'meeting'

    id = db.Column(db.Integer, primary_key=True)

    psychologist_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    student_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    scheduled_at = db.Column(db.DateTime, nullable=False)

    # planned | completed | cancelled и т.п.
    status = db.Column(db.String(20), default='planned')

    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    protocols = db.relationship(
        'MeetingProtocol',
        backref='meeting',
        lazy=True,
        cascade='all, delete-orphan',
    )

    # Отдельные связи к пользователям, чтобы удобно забирать участника и психолога
    student = db.relationship(
        'User',
        foreign_keys=[student_id],
        backref='student_meetings',
        lazy='joined',
    )
    psychologist = db.relationship(
        'User',
        foreign_keys=[psychologist_id],
        backref='psychologist_meetings',
        lazy='joined',
    )

    __table_args__ = (
        UniqueConstraint(
            'student_id',
            'psychologist_id',
            'scheduled_at',
            name='uq_meeting_unique_slot',
        ),
    )


class MeetingRequest(db.Model):
    __tablename__ = 'meeting_request'

    id = db.Column(db.Integer, primary_key=True)

    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    proposed_time = db.Column(db.DateTime, nullable=False)
    status = db.Column(db.String(20), default='pending')

    message = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class MeetingProtocol(db.Model):
    __tablename__ = 'meeting_protocol'

    id = db.Column(db.Integer, primary_key=True)

    meeting_id = db.Column(db.Integer, db.ForeignKey('meeting.id'), nullable=False)

    student_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    psychologist_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    session_date = db.Column(db.DateTime, nullable=False)
    duration = db.Column(db.Integer)  # минуты

    topics_discussed = db.Column(db.Text)
    emotional_state = db.Column(db.Text)
    progress_notes = db.Column(db.Text)
    recommendations = db.Column(db.Text)
    homework = db.Column(db.Text)
    additional_comments = db.Column(db.Text)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    pdf_filename = db.Column(db.String(100))
