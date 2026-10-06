"""
Бизнес-логика, общая для маршрутов и админки: время, тесты и подшкалы,
встречи, анонимные диалоги, удаление пользователя вместе с его данными.
"""
import re
import secrets
from datetime import datetime, timedelta, timezone

from flask import current_app
from sqlalchemy import and_, or_, select

from extensions import db
from models import (
    AnonThread,
    Appointment,
    Article,
    Comment,
    LoginAttempt,
    Meeting,
    MeetingProtocol,
    MeetingRequest,
    Message,
    Post,
    StudentReport,
    Test,
    TestInterpretation,
    TestResult,
    User,
)

# =========================
#   ВРЕМЯ
# =========================
# created_at в базе хранится в UTC (datetime.utcnow), а дата встречи —
# как её ввёл пользователь в форме, то есть местное время.


def local_tz() -> timezone:
    hours = current_app.config.get('APP_UTC_OFFSET_HOURS', 5)
    return timezone(timedelta(hours=hours))


def now_local() -> datetime:
    """Текущее местное время без tzinfo — сравнимо с датами встреч."""
    return datetime.now(local_tz()).replace(tzinfo=None)


def utc_to_local(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value.replace(tzinfo=timezone.utc).astimezone(local_tz()).replace(tzinfo=None)


def parse_local_datetime(raw: str | None) -> datetime | None:
    """Значение <input type="datetime-local"> → datetime или None."""
    raw = (raw or '').strip()
    for fmt in ('%Y-%m-%dT%H:%M', '%Y-%m-%dT%H:%M:%S'):
        try:
            return datetime.strptime(raw, fmt)
        except ValueError:
            continue
    return None


def csv_safe(value) -> str:
    """Защита от формул в Excel: ячейку, начинающуюся с =+-@, экранируем."""
    text = '' if value is None else str(value)
    if text and text[0] in '=+-@\t\r':
        return "'" + text
    return text


# =========================
#   ТЕСТЫ
# =========================

TEST_TYPES = {
    'classic': 'Обычный тест',
    'scale': 'Шкаловая методика',
}

QUESTION_TYPES = {
    'text': 'Текстовый ответ',
    'single_choice': 'Один вариант',
    'multiple_choice': 'Несколько вариантов',
    'scale_choice': 'Шкала',
}

DEFAULT_SCALE = [
    ('Всегда', 'Әрқашан', 4),
    ('Часто', 'Жиі', 3),
    ('Иногда', 'Кейде', 2),
    ('Никогда', 'Ешқашан', 1),
]


def test_has_kazakh(test: Test) -> bool:
    if test.title_kk or test.description_kk:
        return True
    return any(q.text_kk for q in test.questions)


def question_max_score(question) -> int:
    scores = [opt.score or 0 for opt in question.options]
    if not scores:
        return 0
    if question.question_type == 'multiple_choice':
        return sum(s for s in scores if s > 0)
    return max(scores)


def test_max_score(test: Test) -> int:
    return sum(question_max_score(q) for q in test.questions)


def find_interpretation(test: Test, score: int) -> TestInterpretation | None:
    """Подходящий диапазон; при пересечении диапазонов берётся с большим «от»."""
    return (
        TestInterpretation.query.filter(
            TestInterpretation.test_id == test.id,
            TestInterpretation.min_score <= score,
            TestInterpretation.max_score >= score,
        )
        .order_by(TestInterpretation.min_score.desc())
        .first()
    )


def interpretation_text(test: Test, score: int) -> str:
    interp = find_interpretation(test, score)
    if interp:
        return interp.text.strip()
    return f'Итоговый балл: {score}. Интерпретация для этого диапазона не задана.'


def interpretation_issues(test: Test) -> list[str]:
    """Пересечения и пропуски в диапазонах интерпретаций — подсказка психологу."""
    issues = []
    items = sorted(test.interpretations, key=lambda i: (i.min_score, i.max_score))
    for it in items:
        if it.min_score > it.max_score:
            issues.append(f'Диапазон {it.min_score}–{it.max_score}: «от» больше «до».')
    for a, b in zip(items, items[1:]):
        if b.min_score <= a.max_score:
            issues.append(
                f'Диапазоны {a.min_score}–{a.max_score} и {b.min_score}–{b.max_score} '
                f'пересекаются: при совпадении балла берётся второй.'
            )
        elif b.min_score > a.max_score + 1:
            issues.append(
                f'Баллы {a.max_score + 1}–{b.min_score - 1} не попадают ни в один диапазон.'
            )
    if items:
        max_score = test_max_score(test)
        if max_score and items[-1].max_score < max_score:
            issues.append(
                f'Максимально возможный балл теста — {max_score}, '
                f'а последний диапазон заканчивается на {items[-1].max_score}.'
            )
    return issues


def result_is_alert(result: TestResult) -> bool:
    """Тревожный ли результат: по той интерпретации, которая выбрана для его балла."""
    interp = interpretation_for_score(result.test.interpretations, result.score)
    return bool(interp and interp.is_alert)


def alert_results_query(psychologist_id: int, unreviewed_only: bool = False):
    """Результаты по тестам психолога, попавшие в диапазоны «требует внимания»."""
    # Интерпретация, выбранная для балла (при пересечении диапазонов — с большим «от»),
    # должна быть отмечена «требует внимания» — так же, как в тексте результата.
    chosen_is_alert = (
        select(TestInterpretation.is_alert)
        .where(
            TestInterpretation.test_id == TestResult.test_id,
            TestInterpretation.min_score <= TestResult.score,
            TestInterpretation.max_score >= TestResult.score,
        )
        .order_by(TestInterpretation.min_score.desc())
        .limit(1)
        .correlate(TestResult)
        .scalar_subquery()
    )
    query = (
        TestResult.query.join(Test, Test.id == TestResult.test_id)
        .filter(Test.user_id == psychologist_id, chosen_is_alert.is_(True))
    )
    if unreviewed_only:
        query = query.filter(TestResult.reviewed_at.is_(None))
    return query


def pending_alert_count(psychologist_id: int) -> int:
    return alert_results_query(psychologist_id, unreviewed_only=True).count()


def retake_available_from(test: Test, last_result: TestResult | None) -> datetime | None:
    """
    Когда студент может пройти тест (UTC): None — нельзя, иначе момент времени.
    Без предыдущей попытки — сразу.
    """
    if last_result is None:
        return datetime.min
    if test.retake_after_days is None:
        return None
    try:
        return (last_result.created_at or datetime.min) + timedelta(days=max(test.retake_after_days, 0))
    except OverflowError:
        return None


def interpretation_for_score(interpretations, score):
    """Та же логика, что find_interpretation, но по уже загруженному списку."""
    matching = [i for i in interpretations if score is not None and i.min_score <= score <= i.max_score]
    return max(matching, key=lambda i: i.min_score) if matching else None


def group_summary(test: Test, results: list[TestResult], group_sizes: dict) -> list[dict]:
    """
    Сводка по группам: охват, средний балл, распределение по интерпретациям.
    Берётся последняя попытка каждого студента, чтобы повторы не искажали картину.
    """
    latest: dict[int, TestResult] = {}
    for r in results:
        prev = latest.get(r.user_id)
        if prev is None or (r.created_at or datetime.min) >= (prev.created_at or datetime.min):
            latest[r.user_id] = r

    interpretations = list(test.interpretations)
    rows: dict[str, dict] = {}
    for r in latest.values():
        group = r.user.group
        key = group.name if group else 'Без группы'
        row = rows.setdefault(key, {
            'group': key,
            'members': group_sizes.get(group.id, 0) if group else None,
            'passed': 0, 'scores': [], 'bands': {i.id: 0 for i in interpretations},
            'no_band': 0, 'alerts': 0,
        })
        row['passed'] += 1
        if r.score is not None:
            row['scores'].append(r.score)
        interp = interpretation_for_score(interpretations, r.score)
        if interp is None:
            row['no_band'] += 1
        else:
            row['bands'][interp.id] += 1
            if interp.is_alert:
                row['alerts'] += 1

    summary = []
    for key in sorted(rows, key=lambda k: (k == 'Без группы', k)):
        row = rows[key]
        scores = row.pop('scores')
        row['avg'] = round(sum(scores) / len(scores), 1) if scores else None
        row['coverage'] = (round(row['passed'] * 100 / row['members']) if row['members'] else None)
        summary.append(row)
    return summary


# ---------- подшкалы ----------

def parse_question_numbers(raw: str) -> set[int]:
    """«1, 3, 5-7» → {1, 3, 5, 6, 7}. Бросает ValueError при ошибке формата."""
    numbers = set()
    for part in re.split(r'[,\s;]+', raw.strip()):
        if not part:
            continue
        m = re.fullmatch(r'(\d+)(?:-(\d+))?', part)
        if not m:
            raise ValueError(f'Не понимаю «{part}». Пример: 1, 3, 5-7')
        start = int(m.group(1))
        end = int(m.group(2) or start)
        if start < 1 or end < start or end - start > 500:
            raise ValueError(f'Неверный диапазон «{part}»')
        numbers.update(range(start, end + 1))
    if not numbers:
        raise ValueError('Укажите номера вопросов')
    return numbers


def format_question_numbers(numbers: set[int]) -> str:
    """{1, 2, 3, 5} → «1-3, 5»."""
    parts, ordered = [], sorted(numbers)
    i = 0
    while i < len(ordered):
        j = i
        while j + 1 < len(ordered) and ordered[j + 1] == ordered[j] + 1:
            j += 1
        parts.append(str(ordered[i]) if i == j else f'{ordered[i]}-{ordered[j]}')
        i = j + 1
    return ', '.join(parts)


def renumber_subscales_after_delete(test: Test, position: int) -> None:
    """После удаления вопроса с номером position сдвигаем номера в подшкалах."""
    for sub in list(test.subscales):
        try:
            numbers = parse_question_numbers(sub.question_numbers)
        except ValueError:
            continue
        shifted = {n - 1 if n > position else n for n in numbers if n != position}
        if shifted:
            sub.question_numbers = format_question_numbers(shifted)
        else:
            db.session.delete(sub)


def subscale_level(percent: float) -> str:
    if percent < 25:
        return 'низкий уровень проявлений'
    if percent < 50:
        return 'умеренный уровень проявлений'
    if percent < 75:
        return 'повышенный уровень проявлений'
    return 'высокий уровень проявлений'


def per_question_scores(result: TestResult) -> dict[int, int]:
    scores: dict[int, int] = {}
    for answer in result.answers:
        if answer.option is not None:
            scores[answer.question_id] = scores.get(answer.question_id, 0) + (answer.option.score or 0)
    return scores


def subscale_profile(test: Test, scores: dict[int, int]) -> list[dict]:
    """Баллы по подшкалам теста. Вопрос с номером вне теста просто пропускается."""
    if not test.subscales:
        return []
    numbered = {i: q for i, q in enumerate(test.questions, start=1)}
    profile = []
    for sub in test.subscales:
        try:
            numbers = parse_question_numbers(sub.question_numbers)
        except ValueError:
            continue
        questions = [numbered[n] for n in sorted(numbers) if n in numbered]
        score = sum(scores.get(q.id, 0) for q in questions)
        max_score = sum(question_max_score(q) for q in questions)
        percent = round(score * 100 / max_score, 1) if max_score else 0.0
        profile.append({
            'name': sub.name,
            'score': score,
            'max': max_score,
            'percent': percent,
            'level': subscale_level(percent),
            'questions': len(questions),
        })
    return profile


# =========================
#   ВСТРЕЧИ
# =========================

APPOINTMENT_STATUSES = {
    'pending': 'Ожидает подтверждения',
    'confirmed': 'Подтверждена',
    'completed': 'Состоялась',
    'cancelled': 'Отменена',
}

MEETING_STATUS_BY_APPOINTMENT = {
    'pending': 'planned',
    'confirmed': 'planned',
    'completed': 'completed',
    'cancelled': 'cancelled',
}

# Минимальный промежуток между встречами одного психолога
SLOT_GAP = timedelta(minutes=45)


def find_meeting(appointment: Appointment) -> Meeting | None:
    return Meeting.query.filter_by(
        student_id=appointment.student_id,
        psychologist_id=appointment.psychologist_id,
        scheduled_at=appointment.appointment_date,
    ).first()


def meeting_for(appointment: Appointment, create: bool = True) -> Meeting | None:
    """Встреча для протоколов и календаря; статус подтягивается из записи на приём."""
    meeting = find_meeting(appointment)
    if meeting is None and create:
        meeting = Meeting(
            student_id=appointment.student_id,
            psychologist_id=appointment.psychologist_id,
            scheduled_at=appointment.appointment_date,
        )
        db.session.add(meeting)
    if meeting is not None:
        meeting.status = MEETING_STATUS_BY_APPOINTMENT.get(appointment.status, 'planned')
    return meeting


def appointment_for(meeting: Meeting) -> Appointment | None:
    return Appointment.query.filter_by(
        student_id=meeting.student_id,
        psychologist_id=meeting.psychologist_id,
        appointment_date=meeting.scheduled_at,
    ).first()


def schedule_appointment(student: User, psychologist: User, when: datetime,
                         purpose: str | None, requested_by: User) -> tuple[Appointment | None, str | None]:
    """
    Создаёт встречу. Назначенная психологом — сразу подтверждена,
    запрошенная студентом — ждёт подтверждения психолога.
    Возвращает (встреча, None) или (None, текст ошибки).
    """
    if when <= now_local():
        return None, 'Нельзя назначить встречу на прошедшее время'

    busy = Appointment.query.filter(
        Appointment.psychologist_id == psychologist.id,
        Appointment.status.in_(('pending', 'confirmed')),
        Appointment.appointment_date > when - SLOT_GAP,
        Appointment.appointment_date < when + SLOT_GAP,
    ).first()
    if busy:
        if busy.student_id == student.id:
            return None, 'На это время у вас уже есть встреча'
        return None, 'У психолога уже есть встреча в это время, выберите другое'

    status = 'confirmed' if requested_by.role == 'psychologist' else 'pending'

    # Отменённая ранее встреча на тот же слот блокирует уникальный индекс — переиспользуем её
    appointment = Appointment.query.filter_by(
        student_id=student.id,
        psychologist_id=psychologist.id,
        appointment_date=when,
    ).first()
    if appointment is None:
        appointment = Appointment(
            student_id=student.id,
            psychologist_id=psychologist.id,
            appointment_date=when,
        )
        db.session.add(appointment)
    appointment.purpose = purpose or None
    appointment.status = status
    appointment.created_at = datetime.utcnow()
    meeting_for(appointment)
    return appointment, None


# =========================
#   АНОНИМНЫЕ ДИАЛОГИ
# =========================

def get_anon_thread(student_id: int, psychologist_id: int, create: bool = True) -> AnonThread | None:
    thread = AnonThread.query.filter_by(
        student_id=student_id, psychologist_id=psychologist_id
    ).first()
    if thread is None and create:
        thread = AnonThread(
            student_id=student_id,
            psychologist_id=psychologist_id,
            token=secrets.token_urlsafe(24),
        )
        db.session.add(thread)
        db.session.flush()
    return thread


def thread_messages_filter(user_a: int, user_b: int, anonymous: bool):
    return and_(
        or_(
            and_(Message.sender_id == user_a, Message.recipient_id == user_b),
            and_(Message.sender_id == user_b, Message.recipient_id == user_a),
        ),
        Message.is_anonymous.is_(True) if anonymous else or_(
            Message.is_anonymous.is_(False), Message.is_anonymous.is_(None)
        ),
    )


# =========================
#   УДАЛЕНИЕ ПОЛЬЗОВАТЕЛЯ
# =========================

def user_delete_blocker(user: User) -> str | None:
    """Причина, по которой пользователя нельзя удалить, или None."""
    tests = Test.query.filter_by(user_id=user.id).count()
    if tests:
        return (f'У пользователя {user.username} есть тесты ({tests}). '
                'Удалите их или оставьте аккаунт, иначе пропадут результаты студентов.')
    return None


def delete_user_with_data(user: User) -> None:
    """
    Удаляет пользователя и всё, что с ним связано. SQLite не проверяет
    внешние ключи, поэтому без этого оставались бы «висячие» записи,
    из-за которых падали страницы форума и чатов.
    """
    uid = user.id

    for result in TestResult.query.filter_by(user_id=uid).all():
        db.session.delete(result)  # ответы удаляются каскадом

    Comment.query.filter_by(user_id=uid).delete()
    for post in Post.query.filter_by(user_id=uid).all():
        db.session.delete(post)  # комментарии к посту — каскадом
    Article.query.filter_by(user_id=uid).delete()

    Message.query.filter(or_(Message.sender_id == uid, Message.recipient_id == uid)).delete()
    AnonThread.query.filter(or_(AnonThread.student_id == uid, AnonThread.psychologist_id == uid)).delete()
    MeetingRequest.query.filter(or_(MeetingRequest.sender_id == uid, MeetingRequest.receiver_id == uid)).delete()

    StudentReport.query.filter(or_(StudentReport.student_id == uid, StudentReport.psychologist_id == uid)).delete()
    MeetingProtocol.query.filter(or_(MeetingProtocol.student_id == uid, MeetingProtocol.psychologist_id == uid)).delete()
    for meeting in Meeting.query.filter(or_(Meeting.student_id == uid, Meeting.psychologist_id == uid)).all():
        db.session.delete(meeting)
    Appointment.query.filter(or_(Appointment.student_id == uid, Appointment.psychologist_id == uid)).delete()

    LoginAttempt.query.filter_by(username=user.username.lower()).delete()
    db.session.delete(user)
