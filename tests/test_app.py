import io
from datetime import datetime, timedelta

from werkzeug.security import check_password_hash, generate_password_hash

import services
from extensions import db
from flask_app import LEGACY_FALLBACK_TEXTS, _fix_legacy_result_texts, _revoke_leaked_passwords
from models import (
    AnonThread, Appointment, Comment, Meeting, MeetingProtocol, Message, Post, Question,
    QuestionOption, Test, TestAnswer, TestInterpretation, TestResult, TestScaleOption, User,
)
from conftest import CSRF, PASSWORD, Client


# ---------- helpers ----------

def make_scale_test(psych, questions=3, active=True):
    test = Test(title='Шкала тревоги', user_id=psych.id, test_type='scale', is_active=active)
    db.session.add(test)
    db.session.flush()
    for i, (ru, score) in enumerate([('Никогда', 0), ('Иногда', 1), ('Часто', 2)]):
        db.session.add(TestScaleOption(test_id=test.id, order_index=i, label_ru=ru, label_kk=None, score=score))
    db.session.flush()
    for n in range(questions):
        q = Question(test_id=test.id, text=f'Вопрос {n + 1}', question_type='scale_choice')
        db.session.add(q)
        db.session.flush()
        for so in test.scale_options:
            db.session.add(QuestionOption(question_id=q.id, text=so.label_ru, score=so.score))
    db.session.commit()
    return test


def answer_all(test, pick_index):
    return {f'answer_{q.id}': q.options[pick_index].id for q in test.questions}


# ---------- smoke: все страницы открываются ----------

def test_pages_render_for_every_role(app, make_user, client, login_as):
    psych = make_user('psych', role='psychologist')
    student = make_user('100000000001', group='ИС-21')
    admin = make_user('admin', role='superadmin')
    test = make_scale_test(psych)

    public = ['/', '/login', '/register', '/emergency', '/articles', '/psychologists', '/privacy']
    for url in public:
        assert client.get(url).status_code == 200, url
    assert client.get('/posts').status_code == 302  # форум только для своих
    assert client.get('/nope').status_code == 404

    s = login_as(student)
    for url in ['/dashboard', '/tests', '/posts', '/posts/create', '/messages', '/appointments',
                f'/tests/{test.id}/take', f'/messages/{psych.id}', f'/messages/{psych.id}/anonymous',
                '/search?q=тест', '/profile/edit', '/profile/password', f'/profile/{psych.username}']:
        assert s.get(url).status_code == 200, url

    p = login_as(psych)
    for url in ['/dashboard', '/tests', '/tests/create', f'/tests/{test.id}/questions', f'/tests/{test.id}/edit',
                f'/tests/{test.id}/results', f'/tests/{test.id}/take', '/analytics/students',
                f'/analytics/students/{student.id}', f'/analytics/students/{student.id}/report',
                f'/appointments/create/{student.id}', '/appointments', '/messages', f'/messages/{student.id}',
                '/articles/create', '/search?q=Имя', '/api/meetings/calendar',
                f'/tests/{test.id}/questions/{test.questions[0].id}/edit']:
        assert p.get(url).status_code == 200, url

    a = login_as(admin)
    assert a.get('/dashboard').status_code == 302
    for url in ['/admin/', '/admin/groups', '/admin/?group=ИС-21&sort=group_desc', '/tests', '/posts']:
        assert a.get(url).status_code == 200, url


def test_search_page_exists(app, make_user, login_as):
    s = login_as(make_user('100000000001'))
    resp = s.get('/search?q=anything')
    assert resp.status_code == 200
    assert 'Ничего не найдено' in resp.get_data(as_text=True)


# ---------- безопасность ----------

def test_post_without_csrf_is_rejected(app, make_user, login_as):
    s = login_as(make_user('100000000001'))
    resp = s.post('/posts/create', {'title': 'x', 'content': 'y'}, csrf=False)
    assert resp.status_code == 302
    assert Post.query.count() == 0


def test_login_by_email_remember_and_safe_next(app, make_user, client):
    make_user('100000000001')
    resp = client.post('/login', {'username': '100000000001@example.com', 'password': PASSWORD,
                                  'remember': '1', 'next': 'https://evil.example/'})
    assert resp.status_code == 302
    assert resp.headers['Location'].endswith('/dashboard')
    assert 'remember_token' in resp.headers.get('Set-Cookie', '') or any(
        'remember_token' in h for h in resp.headers.getlist('Set-Cookie'))


def test_login_throttling(app, make_user, client):
    make_user('100000000001')
    for _ in range(8):
        client.post('/login', {'username': '100000000001', 'password': 'wrong'})
    resp = client.post('/login', {'username': '100000000001', 'password': PASSWORD})
    assert resp.status_code == 429


def test_forced_password_change(app, make_user, client):
    make_user('100000000001', must_change_password=True)
    resp = client.login('100000000001')
    assert resp.headers['Location'].endswith('/profile/password')
    assert client.get('/dashboard').status_code == 302
    resp = client.post('/profile/password', {'current_password': PASSWORD,
                                             'new_password': 'Another-pass-2', 'new_password2': 'Another-pass-2'})
    assert resp.status_code == 302
    assert client.get('/dashboard').status_code == 200


def test_leaked_passwords_are_revoked(app, make_user):
    make_user('super', role='superadmin', password='Azamat65')
    assert _revoke_leaked_passwords() == ['super']
    user = User.query.filter_by(username='super').first()
    assert not check_password_hash(user.password, 'Azamat65')


def test_register_validation(app, client, make_user):
    make_user('psych', role='psychologist', group='ИС-21')
    from models import Group
    gid = Group.query.first().id
    bad = client.post('/register', {'username': "x');alert(1)//", 'email': 'a@b.cc', 'full_name': 'A',
                                    'password': 'longpassword1', 'password2': 'longpassword1', 'group_id': gid})
    assert bad.status_code == 200 and User.query.count() == 1
    no_consent = client.post('/register', {'username': '100000000009', 'email': 'a@b.cc', 'full_name': 'A',
                                           'password': 'longpassword1', 'password2': 'longpassword1', 'group_id': gid})
    assert no_consent.status_code == 200 and User.query.count() == 1
    ok = client.post('/register', {'username': '100000000009', 'email': 'a@b.cc', 'full_name': 'A',
                                   'password': 'longpassword1', 'password2': 'longpassword1', 'group_id': gid,
                                   'accept_privacy': '1'})
    assert ok.status_code == 302 and User.query.count() == 2
    assert User.query.filter_by(username='100000000009').one().privacy_accepted_at is not None


def test_upload_rejects_non_images(app, make_user, login_as):
    s = login_as(make_user('100000000001'))
    resp = s.post('/profile/edit', {'full_name': 'Тест',
                                    'profile_pic': (io.BytesIO(b'<script>alert(1)</script>'), 'x.png')},
                  content_type='multipart/form-data')
    assert resp.status_code == 302
    assert User.query.filter_by(username='100000000001').first().profile_pic is None

    png = b'\x89PNG\r\n\x1a\n' + b'\x00' * 64
    s.post('/profile/edit', {'full_name': 'Тест', 'profile_pic': (io.BytesIO(png), 'me.png')},
           content_type='multipart/form-data')
    assert User.query.filter_by(username='100000000001').first().profile_pic.endswith('.png')


def test_student_cannot_view_other_student_profile(app, make_user, login_as):
    make_user('100000000002')
    s = login_as(make_user('100000000001'))
    assert s.get('/profile/100000000002').status_code == 403


# ---------- тесты: прохождение и подсчёт ----------

def test_take_test_requires_all_answers_and_scores(app, make_user, login_as):
    psych = make_user('psych', role='psychologist')
    student = make_user('100000000001')
    test = make_scale_test(psych)
    db.session.add(TestInterpretation(test_id=test.id, min_score=4, max_score=6, text='Высокая тревога', is_alert=True))
    db.session.commit()

    s = login_as(student)
    partial = answer_all(test, 2)
    partial.pop(f'answer_{test.questions[0].id}')
    resp = s.post(f'/tests/{test.id}/take', {**partial, 'lang': 'ru'})
    assert resp.status_code == 200 and TestResult.query.count() == 0

    resp = s.post(f'/tests/{test.id}/take', {**answer_all(test, 2), 'lang': 'ru'})
    assert resp.status_code == 302
    result = TestResult.query.one()
    assert result.score == 6 and result.result_text == 'Высокая тревога'

    # студент не видит интерпретацию, психолог видит ответы и отметку «внимание»
    assert 'Высокая тревога' not in s.get(f'/test_result/{result.id}').get_data(as_text=True)
    p = login_as(psych)
    page = p.get(f'/test_result/{result.id}').get_data(as_text=True)
    assert 'Высокая тревога' in page and 'требует внимания' in page
    assert 'Высокая тревога' in p.get('/dashboard').get_data(as_text=True)


def test_option_from_other_question_is_rejected(app, make_user, login_as):
    psych = make_user('psych', role='psychologist')
    test = make_scale_test(psych)
    other = make_scale_test(psych)
    s = login_as(make_user('100000000001'))
    data = answer_all(test, 0)
    data[f'answer_{test.questions[0].id}'] = other.questions[0].options[2].id
    s.post(f'/tests/{test.id}/take', data)
    assert TestResult.query.count() == 0


def test_multiple_choice_answers_are_all_saved(app, make_user, login_as):
    psych = make_user('psych', role='psychologist')
    test = Test(title='MC', user_id=psych.id, test_type='classic')
    db.session.add(test)
    db.session.flush()
    q = Question(test_id=test.id, text='Что беспокоит?', question_type='multiple_choice')
    db.session.add(q)
    db.session.flush()
    opts = [QuestionOption(question_id=q.id, text=t, score=s) for t, s in [('Сон', 1), ('Учёба', 2), ('Ничего', 0)]]
    db.session.add_all(opts)
    db.session.commit()

    s = login_as(make_user('100000000001'))
    s.post(f'/tests/{test.id}/take', {f'answer_{q.id}': [opts[0].id, opts[1].id]})
    result = TestResult.query.one()
    assert result.score == 3
    assert TestAnswer.query.filter_by(test_result_id=result.id).count() == 2


def test_psychologist_preview_does_not_save(app, make_user, login_as):
    psych = make_user('psych', role='psychologist')
    test = make_scale_test(psych)
    p = login_as(psych)
    p.post(f'/tests/{test.id}/take', answer_all(test, 1))
    assert TestResult.query.count() == 0


def test_scale_update_syncs_existing_questions_and_recalculates(app, make_user, login_as):
    psych = make_user('psych', role='psychologist')
    test = make_scale_test(psych, questions=2)
    s = login_as(make_user('100000000001'))
    s.post(f'/tests/{test.id}/take', answer_all(test, 2))
    assert TestResult.query.one().score == 4

    p = login_as(psych)
    p.post(f'/tests/{test.id}/scale-options', {
        'scale_label_ru[]': ['Нет', 'Иногда', 'Часто'], 'scale_label_kk[]': ['', '', ''],
        'scale_score[]': ['0', '1', '5'],
    })
    assert [o.text for o in test.questions[0].options] == ['Нет', 'Иногда', 'Часто']
    assert test.questions[1].options[2].score == 5
    p.post(f'/tests/{test.id}/recalculate')
    assert TestResult.query.one().score == 10


def test_subscales_profile_and_exports(app, make_user, login_as):
    psych = make_user('psych', role='psychologist')
    test = make_scale_test(psych, questions=4)
    s = login_as(make_user('100000000001', group='ИС-21'))
    s.post(f'/tests/{test.id}/take', answer_all(test, 2))

    p = login_as(psych)
    p.post(f'/tests/{test.id}/subscales', {'name': 'Первая пара', 'question_numbers': '1-2'})
    result = TestResult.query.one()
    page = p.get(f'/test_result/{result.id}').get_data(as_text=True)
    assert 'Первая пара' in page and '4 из 4' in page

    csv_resp = p.get(f'/tests/{test.id}/export.csv')
    text = csv_resp.get_data(as_text=True)
    assert csv_resp.status_code == 200 and 'Подшкала: Первая пара' in text and 'ИС-21' in text

    pdf = p.get(f'/tests/{test.id}/download_results')
    assert pdf.status_code == 200 and pdf.data.startswith(b'%PDF')


def test_interpretation_delete_checks_test_ownership(app, make_user, login_as):
    psych = make_user('psych', role='psychologist')
    other_psych = make_user('psych2', role='psychologist')
    foreign = make_scale_test(other_psych)
    interp = TestInterpretation(test_id=foreign.id, min_score=0, max_score=1, text='x')
    db.session.add(interp)
    db.session.commit()
    mine = make_scale_test(psych)
    p = login_as(psych)
    resp = p.post(f'/tests/{mine.id}/add_interpretation', {'delete_interpretation': interp.id})
    assert resp.status_code == 404
    assert db.session.get(TestInterpretation, interp.id) is not None


def test_delete_test_with_results_needs_confirmation(app, make_user, login_as):
    psych = make_user('psych', role='psychologist')
    test = make_scale_test(psych)
    login_as(make_user('100000000001')).post(f'/tests/{test.id}/take', answer_all(test, 0))
    p = login_as(psych)
    p.post(f'/tests/{test.id}/delete')
    assert db.session.get(Test, test.id) is not None
    p.post(f'/tests/{test.id}/delete', {'confirm_results': '1'})
    assert db.session.get(Test, test.id) is None


def test_legacy_fallback_text_is_replaced(app, make_user):
    psych = make_user('psych', role='psychologist')
    student = make_user('100000000001')
    test = make_scale_test(psych)
    db.session.add(TestResult(user_id=student.id, test_id=test.id, score=45, result_text=LEGACY_FALLBACK_TEXTS[2]))
    db.session.commit()
    assert _fix_legacy_result_texts() == 1
    assert 'в норме' not in TestResult.query.one().result_text


# ---------- сообщения ----------

def test_anonymous_chat_hides_student_identity(app, make_user, login_as):
    psych = make_user('psych', role='psychologist')
    student = make_user('100000000001', full_name='Секретная Студентка')
    s = login_as(student)
    s.post(f'/messages/{psych.id}/anonymous', {'content': 'Мне тяжело'})
    msg = Message.query.one()
    assert msg.is_anonymous

    p = login_as(psych)
    inbox = p.get('/messages').get_data(as_text=True)
    assert 'Секретная' not in inbox and '100000000001' not in inbox
    thread = AnonThread.query.one()
    assert thread.alias in inbox
    page = p.get(f'/messages/anonymous/{thread.token}').get_data(as_text=True)
    assert 'Мне тяжело' in page and 'Секретная' not in page and f'/analytics/students/{student.id}' not in page

    p.post(f'/messages/anonymous/{thread.token}', {'content': 'Я рядом'})
    reply = Message.query.filter_by(sender_id=psych.id).one()
    assert reply.is_anonymous and reply.recipient_id == student.id
    assert 'Я рядом' in s.get(f'/messages/{psych.id}/anonymous').get_data(as_text=True)
    # в ленте обычного чата анонимных сообщений нет (в списке диалогов слева — есть)
    named = s.get(f'/messages/{psych.id}').get_data(as_text=True)
    assert '<div class="text-pre">Я рядом</div>' not in named
    assert '<div class="text-pre">Я рядом</div>' in s.get(f'/messages/{psych.id}/anonymous').get_data(as_text=True)


def test_messages_only_between_student_and_psychologist(app, make_user, login_as):
    other = make_user('100000000002')
    s = login_as(make_user('100000000001'))
    s.post(f'/messages/{other.id}', {'content': 'привет'})
    assert Message.query.count() == 0


# ---------- встречи ----------

def test_appointment_lifecycle(app, make_user, login_as):
    psych = make_user('psych', role='psychologist')
    student = make_user('100000000001')
    s = login_as(student)
    when = (services.now_local() + timedelta(days=2)).replace(second=0, microsecond=0)

    past = (services.now_local() - timedelta(days=1)).strftime('%Y-%m-%dT%H:%M')
    s.post(f'/messages/{psych.id}', {'appointment_date': past, 'purpose': 'x'})
    assert Appointment.query.count() == 0

    s.post(f'/messages/{psych.id}', {'appointment_date': when.strftime('%Y-%m-%dT%H:%M'), 'purpose': 'Поговорить'})
    appt = Appointment.query.one()
    assert appt.status == 'pending'
    assert Meeting.query.one().status == 'planned'

    # студент не может подтвердить сам
    assert s.post(f'/appointments/{appt.id}/update', {'action': 'confirm'}).status_code == 403

    p = login_as(psych)
    p.post(f'/appointments/{appt.id}/update', {'action': 'confirm'})
    assert db.session.get(Appointment, appt.id).status == 'confirmed'
    assert 'Поговорить' in s.get('/appointments').get_data(as_text=True)

    # занятый слот
    other = make_user('100000000002')
    p.post(f'/appointments/create/{other.id}', {'appointment_date': (when + timedelta(minutes=15)).strftime('%Y-%m-%dT%H:%M')})
    assert Appointment.query.count() == 1

    s.post(f'/appointments/{appt.id}/update', {'action': 'cancel'})
    assert db.session.get(Appointment, appt.id).status == 'cancelled'
    assert Meeting.query.one().status == 'cancelled'


def test_protocol_marks_meeting_completed_and_is_private(app, make_user, login_as):
    psych = make_user('psych', role='psychologist')
    student = make_user('100000000001')
    p = login_as(psych)
    when = services.now_local() + timedelta(hours=3)
    p.post(f'/appointments/create/{student.id}', {'appointment_date': when.strftime('%Y-%m-%dT%H:%M')})
    appt = Appointment.query.one()
    assert appt.status == 'confirmed'

    meeting = Meeting.query.one()
    # до встречи протокол не заполняется
    p.post(f'/meetings/{meeting.id}/create_protocol', {'duration': '45', 'topics_discussed': 'Сон'})
    assert MeetingProtocol.query.count() == 0 and db.session.get(Appointment, appt.id).status == 'confirmed'

    # «прошло время»: переносим встречу в прошлое
    past = services.now_local() - timedelta(hours=1)
    appt.appointment_date = past
    meeting.scheduled_at = past
    db.session.commit()
    p.post(f'/meetings/{meeting.id}/create_protocol', {'duration': '45', 'topics_discussed': 'Сон'})
    assert db.session.get(Meeting, meeting.id).status == 'completed'
    assert db.session.get(Appointment, appt.id).status == 'completed'

    protocol = MeetingProtocol.query.one()
    resp = p.get(f'/protocols/{protocol.id}/download')
    assert resp.status_code == 200 and resp.data.startswith(b'%PDF')
    s = login_as(student)
    assert s.get(f'/protocols/{protocol.id}/download').status_code == 403
    assert 'Сон' not in s.get('/appointments').get_data(as_text=True)


def test_report_pdf(app, make_user, login_as):
    psych = make_user('psych', role='psychologist')
    student = make_user('100000000001', group='ИС-21')
    p = login_as(psych)
    p.post(f'/analytics/students/{student.id}/report', {'emotional_state': 'Стабильное ' * 200})
    from models import StudentReport
    report = StudentReport.query.one()
    resp = p.get(f'/analytics/students/{student.id}/report/{report.id}/download')
    assert resp.status_code == 200 and resp.data.startswith(b'%PDF')


# ---------- форум ----------

def test_anonymous_post_and_moderation(app, make_user, login_as, client):
    psych = make_user('psych', role='psychologist')
    student = make_user('100000000001', full_name='Тайный Автор')
    s = login_as(student)
    s.post('/posts/create', {'title': 'Тревога', 'content': 'Текст', 'is_anonymous': '1'})
    post = Post.query.one()
    assert post.is_anonymous

    other = login_as(make_user('100000000002'))
    for url in ['/posts', f'/posts/{post.id}', '/']:
        assert 'Тайный' not in other.get(url).get_data(as_text=True), url
    assert other.get(f'/posts/{post.id}/edit').status_code == 403

    other.post(f'/posts/{post.id}/comment', {'content': 'Держись'})
    comment = Comment.query.one()
    assert s.post(f'/comments/{comment.id}/delete').status_code == 403

    p = login_as(psych)
    p.post(f'/comments/{comment.id}/delete')
    assert Comment.query.count() == 0
    p.post(f'/posts/{post.id}/delete')
    assert Post.query.count() == 0


def test_index_hides_forum_from_guests(app, make_user, client):
    student = make_user('100000000001')
    db.session.add(Post(title='Личное', content='...', user_id=student.id))
    db.session.commit()
    assert 'Личное' not in client.get('/').get_data(as_text=True)


# ---------- админка ----------

def test_admin_delete_user_removes_related_data(app, make_user, login_as):
    psych = make_user('psych', role='psychologist')
    student = make_user('100000000001')
    test = make_scale_test(psych)
    s = login_as(student)
    s.post(f'/tests/{test.id}/take', answer_all(test, 0))
    s.post('/posts/create', {'title': 'Пост', 'content': 'Текст'})
    s.post(f'/messages/{psych.id}', {'content': 'Привет'})

    admin = make_user('admin', role='superadmin')
    a = login_as(admin)
    a.post(f'/admin/users/{student.id}/delete')
    assert db.session.get(User, student.id) is None
    assert TestResult.query.count() == 0 and Post.query.count() == 0 and Message.query.count() == 0
    # страницы, где раньше падало на «висячих» записях
    assert login_as(psych).get('/posts').status_code == 200

    # психолога с тестами удалить нельзя, себя — тоже
    a.post(f'/admin/users/{psych.id}/delete')
    assert db.session.get(User, psych.id) is not None
    a.post(f'/admin/users/{admin.id}/delete')
    assert db.session.get(User, admin.id) is not None


def test_admin_role_limits(app, make_user, login_as):
    admin = make_user('admin', role='admin')
    superadmin = make_user('root', role='superadmin')
    a = login_as(admin)
    a.post('/admin/users/create', {'username': 'evil', 'email': 'evil@example.com', 'role': 'superadmin'})
    assert User.query.filter_by(username='evil').first() is None
    a.post(f'/admin/users/{superadmin.id}/delete')
    assert db.session.get(User, superadmin.id) is not None
    a.post(f'/admin/users/{admin.id}/role', {'role': 'superadmin'})
    assert db.session.get(User, admin.id).role == 'admin'
    assert login_as(make_user('100000000001')).get('/admin/').status_code == 403


def test_bulk_import_generates_passwords(app, make_user, login_as):
    a = login_as(make_user('root', role='superadmin'))
    csv_data = 'username;email;full_name;group\n100000000111;a1@example.com;Студент Один;ИС-22\n'
    preview = a.post('/admin/users/bulk_upload', {'mode': 'create_only',
                                                  'csv': (io.BytesIO(csv_data.encode('utf-8')), 'u.csv')},
                     content_type='multipart/form-data')
    html = preview.get_data(as_text=True)
    import re
    plan = re.search(r'name="plan_b64" value="([^"]+)"', html).group(1)
    result = a.post('/admin/users/bulk_upload', {'confirm': '1', 'mode': 'create_only', 'plan_b64': plan})
    assert 'new_users_passwords.csv' in result.get_data(as_text=True)
    user = User.query.filter_by(username='100000000111').one()
    assert user.must_change_password
    assert not check_password_hash(user.password, '100000000111abc')
    assert user.group.name == 'ИС-22'


def test_admin_groups(app, make_user, login_as):
    a = login_as(make_user('root', role='superadmin'))
    a.post('/admin/groups/create', {'name': 'ПК-31', 'course': '3'})
    from models import Group
    g = Group.query.filter_by(name='ПК-31').one()
    a.post(f'/admin/groups/{g.id}/update', {'name': 'ПК-32', 'course': '3'})
    assert db.session.get(Group, g.id).name == 'ПК-32'
    a.post(f'/admin/groups/{g.id}/delete')
    assert db.session.get(Group, g.id) is None


# ---------- регрессии по итогам ревью ----------

def test_scale_resave_keeps_reverse_keyed_questions(app, make_user, login_as):
    psych = make_user('psych', role='psychologist')
    test = make_scale_test(psych, questions=2)
    reverse_q = test.questions[1]
    for opt, score in zip(reverse_q.options, [2, 1, 0]):
        opt.score = score
    db.session.commit()
    login_as(make_user('100000000001')).post(f'/tests/{test.id}/take', answer_all(test, 0))

    p = login_as(psych)
    form = {'scale_label_ru[]': ['Никогда', 'Иногда', 'Часто'], 'scale_label_kk[]': ['Ешқашан', '', ''],
            'scale_score[]': ['0', '1', '2']}
    p.post(f'/tests/{test.id}/scale-options', form)
    assert [o.score for o in db.session.get(Question, reverse_q.id).options] == [2, 1, 0]
    assert test.questions[0].options[0].text_kk == 'Ешқашан'

    # тест уже проходили — менять число вариантов нельзя
    p.post(f'/tests/{test.id}/scale-options', {'scale_label_ru[]': ['Нет', 'Да'], 'scale_label_kk[]': ['', ''],
                                               'scale_score[]': ['0', '1']})
    assert len(db.session.get(Test, test.id).scale_options) == 3
    assert len(test.questions[0].options) == 3


def test_answered_question_cannot_be_deleted_and_subscales_renumber(app, make_user, login_as):
    from models import TestSubscale
    psych = make_user('psych', role='psychologist')
    test = make_scale_test(psych, questions=4)
    db.session.add(TestSubscale(test_id=test.id, name='Хвост', question_numbers='3-4'))
    db.session.commit()
    p = login_as(psych)
    p.post(f'/tests/{test.id}/questions', {'delete_question': test.questions[0].id})
    assert len(db.session.get(Test, test.id).questions) == 3
    assert TestSubscale.query.one().question_numbers == '2-3'

    login_as(make_user('100000000001')).post(f'/tests/{test.id}/take', answer_all(test, 1))
    p.post(f'/tests/{test.id}/questions', {'delete_question': test.questions[0].id})
    assert len(db.session.get(Test, test.id).questions) == 3


def test_csv_upsert_keeps_missing_columns_and_skips_self(app, make_user, login_as):
    import re
    root = make_user('root', role='superadmin')
    psych = make_user('psych', role='psychologist', group='ПК-31')
    a = login_as(root)
    csv_data = 'username,email\nroot,root@example.com\npsych,new-psych@example.com\n'
    preview = a.post('/admin/users/bulk_upload', {'mode': 'upsert',
                                                  'csv': (io.BytesIO(csv_data.encode()), 'u.csv')},
                     content_type='multipart/form-data')
    plan = re.search(r'name="plan_b64" value="([^"]+)"', preview.get_data(as_text=True)).group(1)
    a.post('/admin/users/bulk_upload', {'confirm': '1', 'mode': 'upsert', 'plan_b64': plan})
    psych = db.session.get(User, psych.id)
    assert psych.role == 'psychologist' and psych.group.name == 'ПК-31'
    assert psych.email == 'new-psych@example.com'
    assert db.session.get(User, root.id).role == 'superadmin'


def test_role_change_does_not_reveal_anonymous_student(app, make_user, login_as):
    psych = make_user('psych', role='psychologist')
    student = make_user('100000000001', full_name='Секретная Студентка')
    login_as(student).post(f'/messages/{psych.id}/anonymous', {'content': 'Тайна'})
    login_as(psych).get('/messages')  # создаётся AnonThread
    psych.role = 'student'
    db.session.commit()
    page = login_as(psych).get('/messages').get_data(as_text=True)
    assert 'Секретная' not in page and 'Аноним #' in page


def test_failed_logins_from_other_ip_do_not_lock_owner(app, make_user):
    make_user('100000000001')
    attacker = Client(app)
    for i in range(10):
        attacker.c.post('/login', data={'username': '100000000001', 'password': 'wrong', '_csrf_token': CSRF},
                        headers={'X-Real-IP': f'10.0.0.{i % 2}'})
    owner = Client(app)
    resp = owner.c.post('/login', data={'username': '100000000001', 'password': PASSWORD, '_csrf_token': CSRF},
                        headers={'X-Real-IP': '192.168.1.5'})
    assert resp.status_code == 302


def test_password_change_ends_other_sessions(app, make_user, login_as):
    user = make_user('100000000001')
    stolen = login_as(user)
    owner = login_as(user)
    owner.post('/profile/password', {'current_password': PASSWORD,
                                     'new_password': 'Fresh-pass-77', 'new_password2': 'Fresh-pass-77'})
    assert owner.get('/dashboard').status_code == 200
    assert stolen.get('/dashboard').status_code == 302


def test_appointment_actions_respect_dates(app, make_user, login_as):
    psych = make_user('psych', role='psychologist')
    student = make_user('100000000001')
    p = login_as(psych)
    future = services.now_local() + timedelta(days=1)
    p.post(f'/appointments/create/{student.id}', {'appointment_date': future.strftime('%Y-%m-%dT%H:%M')})
    appt = Appointment.query.one()
    p.post(f'/appointments/{appt.id}/update', {'action': 'complete'})
    assert db.session.get(Appointment, appt.id).status == 'confirmed'

    appt.appointment_date = services.now_local() - timedelta(hours=2)
    db.session.commit()
    s = login_as(student)
    s.post(f'/appointments/{appt.id}/update', {'action': 'cancel'})
    assert db.session.get(Appointment, appt.id).status == 'confirmed'
    p.post(f'/appointments/{appt.id}/update', {'action': 'complete'})
    assert db.session.get(Appointment, appt.id).status == 'completed'


def test_admin_can_edit_own_profile_and_bad_pagination_params(app, make_user, login_as):
    admin = make_user('admin', role='admin')
    a = login_as(admin)
    resp = a.post(f'/admin/users/{admin.id}/update', {'full_name': 'Новое Имя', 'email': 'admin@example.com',
                                                      'role': 'admin'})
    assert resp.status_code == 302 and db.session.get(User, admin.id).full_name == 'Новое Имя'
    for i in range(7):
        make_user(f'10000000010{i}')
    page = a.get('/admin/?per_page=5&endpoint=x&_external=1&_anchor=evil')
    assert page.status_code == 200
    html = page.get_data(as_text=True)
    assert 'page=2' in html and '#evil' not in html and 'http://localhost' not in html


# ---------- продуманные сценарии ----------

def _alert_setup(make_user, login_as):
    psych = make_user('psych', role='psychologist')
    test = make_scale_test(psych)
    db.session.add(TestInterpretation(test_id=test.id, min_score=4, max_score=6, text='Риск', is_alert=True))
    db.session.add(TestInterpretation(test_id=test.id, min_score=0, max_score=3, text='Норма'))
    db.session.commit()
    return psych, test


def test_alert_review_workflow(app, make_user, login_as):
    psych, test = _alert_setup(make_user, login_as)
    s = login_as(make_user('100000000001', group='ИС-21'))
    s.post(f'/tests/{test.id}/take', answer_all(test, 2))
    result = TestResult.query.one()

    p = login_as(psych)
    assert 'Риск' in p.get('/alerts').get_data(as_text=True)
    assert services.pending_alert_count(psych.id) == 1
    assert 'внимание' in p.get('/analytics/students').get_data(as_text=True)

    other = login_as(make_user('psych2', role='psychologist'))
    assert other.post(f'/test_result/{result.id}/review', {'action': 'review'}).status_code == 403

    p.post(f'/test_result/{result.id}/review', {'action': 'review', 'note': 'Позвонили, всё в порядке'})
    result = db.session.get(TestResult, result.id)
    assert result.reviewed_at and result.reviewed_by_id == psych.id
    assert result.psychologist_note == 'Позвонили, всё в порядке'
    assert services.pending_alert_count(psych.id) == 0
    assert 'Риск' not in p.get('/alerts').get_data(as_text=True)

    p.post(f'/test_result/{result.id}/review', {'action': 'reopen'})
    assert services.pending_alert_count(psych.id) == 1


def test_bulk_alert_review(app, make_user, login_as):
    psych, test = _alert_setup(make_user, login_as)
    for i in range(3):
        login_as(make_user(f'10000000000{i}')).post(f'/tests/{test.id}/take', answer_all(test, 2))
    ids = [r.id for r in TestResult.query.all()]
    login_as(psych).post('/alerts', {'result_ids[]': [str(x) for x in ids[:2]]})
    assert services.pending_alert_count(psych.id) == 1


def test_student_sees_support_only_for_alert_result(app, make_user, login_as):
    psych, test = _alert_setup(make_user, login_as)
    s = login_as(make_user('100000000001'))
    s.post(f'/tests/{test.id}/take', answer_all(test, 2))
    page = s.get(f'/test_result/{TestResult.query.one().id}').get_data(as_text=True)
    assert 'может быть непросто' in page and 'tel:150' in page and 'Риск' not in page

    test.retake_after_days = 0
    db.session.commit()
    s.post(f'/tests/{test.id}/take', answer_all(test, 0))
    calm = TestResult.query.order_by(TestResult.id.desc()).first()
    assert 'может быть непросто' not in s.get(f'/test_result/{calm.id}').get_data(as_text=True)


def test_retake_policy(app, make_user, login_as):
    psych = make_user('psych', role='psychologist')
    test = make_scale_test(psych)
    s = login_as(make_user('100000000001'))
    s.post(f'/tests/{test.id}/take', answer_all(test, 0))
    # по умолчанию — один раз
    assert s.get(f'/tests/{test.id}/take').status_code == 302
    s.post(f'/tests/{test.id}/take', answer_all(test, 1))
    assert TestResult.query.count() == 1
    assert 'пройден' in s.get('/tests').get_data(as_text=True)

    p = login_as(psych)
    p.post(f'/tests/{test.id}/edit', {'title': test.title, 'is_active': 'on', 'retake_after_days': '30'})
    assert db.session.get(Test, test.id).retake_after_days == 30
    assert s.get(f'/tests/{test.id}/take').status_code == 302
    assert 'повторно — с' in s.get('/tests').get_data(as_text=True)

    # прошло 31 день
    r = TestResult.query.one()
    r.created_at = r.created_at - timedelta(days=31)
    db.session.commit()
    assert 'Пройти снова' in s.get('/tests').get_data(as_text=True)
    s.post(f'/tests/{test.id}/take', answer_all(test, 2))
    assert TestResult.query.count() == 2

    # история попыток у психолога
    latest = TestResult.query.order_by(TestResult.id.desc()).first()
    assert 'Все попытки этого студента' in p.get(f'/test_result/{latest.id}').get_data(as_text=True)


def test_group_summary_uses_latest_attempt_and_coverage(app, make_user, login_as):
    psych, test = _alert_setup(make_user, login_as)
    test.retake_after_days = 0
    db.session.commit()
    a = make_user('100000000001', group='ИС-21')
    make_user('100000000002', group='ИС-21')  # не проходил
    s = login_as(a)
    s.post(f'/tests/{test.id}/take', answer_all(test, 2))  # 6 — риск
    s.post(f'/tests/{test.id}/take', answer_all(test, 0))  # 0 — норма, последняя
    from models import Group
    sizes = {Group.query.filter_by(name='ИС-21').one().id: 2}
    summary = services.group_summary(db.session.get(Test, test.id), TestResult.query.all(), sizes)
    row = summary[0]
    assert row['group'] == 'ИС-21' and row['passed'] == 1 and row['members'] == 2 and row['coverage'] == 50
    assert row['alerts'] == 0 and row['avg'] == 0
    page = login_as(psych).get(f'/tests/{test.id}/results').get_data(as_text=True)
    assert 'Сводка по группам' in page and '1 из 2' in page


def test_chat_partial_returns_only_new_messages(app, make_user, login_as):
    psych = make_user('psych', role='psychologist')
    student = make_user('100000000001')
    s = login_as(student)
    s.post(f'/messages/{psych.id}', {'content': 'Первое'})
    first = Message.query.one()
    p = login_as(psych)
    p.post(f'/messages/{student.id}', {'content': 'Ответ психолога'})
    html = s.get(f'/messages/{psych.id}?partial=1&after={first.id}').get_data(as_text=True)
    assert 'Ответ психолога' in html and 'Первое' not in html and '<html' not in html
    assert Message.query.filter_by(sender_id=psych.id).one().is_read


# ---------- регрессии по ревью сценариев ----------

def test_dashboard_checkmark_keeps_note(app, make_user, login_as):
    psych, test = _alert_setup(make_user, login_as)
    login_as(make_user('100000000001')).post(f'/tests/{test.id}/take', answer_all(test, 2))
    result = TestResult.query.one()
    p = login_as(psych)
    p.post(f'/test_result/{result.id}/review', {'action': 'note', 'note': 'Звонили маме'})
    p.post(f'/test_result/{result.id}/review', {'action': 'review', 'next': '/dashboard'})
    result = db.session.get(TestResult, result.id)
    assert result.reviewed_at and result.psychologist_note == 'Звонили маме'


def test_overlapping_ranges_use_the_chosen_interpretation(app, make_user, login_as):
    psych = make_user('psych', role='psychologist')
    test = make_scale_test(psych)
    db.session.add_all([
        TestInterpretation(test_id=test.id, min_score=3, max_score=6, text='Риск', is_alert=True),
        TestInterpretation(test_id=test.id, min_score=5, max_score=6, text='Норма'),
    ])
    db.session.commit()
    s = login_as(make_user('100000000001'))
    s.post(f'/tests/{test.id}/take', answer_all(test, 2))  # 6 баллов → «Норма» (больший «от»)
    result = TestResult.query.one()
    assert result.result_text == 'Норма'
    assert services.pending_alert_count(psych.id) == 0
    assert not services.result_is_alert(result)
    assert 'может быть непросто' not in s.get(f'/test_result/{result.id}').get_data(as_text=True)


def test_retake_interval_validation_and_time_display(app, make_user, login_as):
    import re
    psych = make_user('psych', role='psychologist')
    test = make_scale_test(psych)
    p = login_as(psych)
    for bad in ['3000000', '99999999999999999999', '1e3', '-1']:
        p.post(f'/tests/{test.id}/edit', {'title': test.title, 'is_active': 'on', 'retake_after_days': bad})
        assert db.session.get(Test, test.id).retake_after_days is None, bad
    p.post(f'/tests/{test.id}/edit', {'title': test.title, 'is_active': 'on', 'retake_after_days': '1'})
    s = login_as(make_user('100000000001'))
    s.post(f'/tests/{test.id}/take', answer_all(test, 0))
    page = s.get('/tests').get_data(as_text=True)
    assert re.search(r'повторно — с \d{2}\.\d{2}\.\d{4} \d{2}:\d{2}', page)


def test_history_with_missing_score_and_bulk_garbage_ids(app, make_user, login_as):
    psych, test = _alert_setup(make_user, login_as)
    student = make_user('100000000001')
    db.session.add(TestResult(user_id=student.id, test_id=test.id, score=None, result_text='старый',
                              created_at=datetime.utcnow() - timedelta(days=3)))
    db.session.commit()
    test.retake_after_days = 0
    db.session.commit()
    login_as(student).post(f'/tests/{test.id}/take', answer_all(test, 2))
    latest = TestResult.query.order_by(TestResult.id.desc()).first()
    p = login_as(psych)
    page = p.get(f'/test_result/{latest.id}').get_data(as_text=True)
    assert 'None' not in page and '(+' not in page
    assert p.post('/alerts', {'result_ids[]': ['²', 'abc', str(latest.id)]}).status_code == 302
    assert services.pending_alert_count(psych.id) == 0


def test_chat_partial_marker_and_anonymous_times(app, make_user, login_as):
    import re
    psych = make_user('psych', role='psychologist')
    student = make_user('100000000001')
    s = login_as(student)
    s.post(f'/messages/{psych.id}/anonymous', {'content': 'Мне плохо'})
    resp = s.get(f'/messages/{psych.id}/anonymous?partial=1&after=0')
    assert resp.headers.get('X-Chat-Partial') == '1'
    p = login_as(psych)
    p.get('/messages')
    token = AnonThread.query.one().token
    html = p.get(f'/messages/anonymous/{token}?partial=1&after=0').get_data(as_text=True)
    assert 'Мне плохо' in html and not re.search(r'\d{2}:\d{2}', html)
