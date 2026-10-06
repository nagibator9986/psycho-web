# PsyStudentHelp

Платформа психологической поддержки студентов: психологические тесты на русском и казахском,
переписка с психологом (в том числе анонимная), запись на встречи, протоколы и отчёты,
форум, статьи и панель администратора.

Стек: Flask 3, Flask-SQLAlchemy, Flask-Login, SQLite, ReportLab (PDF), Bootstrap 5.

## Роли

| Роль | Что может |
|---|---|
| Студент | проходит тесты, пишет психологу открыто или анонимно, записывается на встречу, пишет на форум (можно анонимно) |
| Психолог | создаёт тесты, шкалы, интерпретации и подшкалы; видит результаты и ответы; выгружает PDF/CSV; ведёт встречи, протоколы, отчёты; модерирует форум |
| Администратор | управляет студентами и психологами, группами, массовым импортом из CSV |
| Суперадмин | всё, что администратор, плюс управление администраторами |

## Запуск локально

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
flask --app flask_app create-superadmin admin admin@example.com
flask --app flask_app run
```

База создаётся в `instance/psych_help.db`. Недостающие таблицы и колонки добавляются
автоматически при запуске (`schema.py`), данные не трогаются.

Тесты:

```bash
pip install pytest
python3 -m pytest -q
```

## Настройки (переменные окружения)

| Переменная | Назначение | По умолчанию |
|---|---|---|
| `SECRET_KEY` | ключ подписи сессий | случайный, хранится в `instance/secret_key` |
| `DATABASE_URL` | строка подключения SQLAlchemy | `sqlite:///psych_help.db` (в `instance/`) |
| `SESSION_COOKIE_SECURE` | `1` — cookie только по HTTPS (включите на проде с HTTPS) | выключено |
| `APP_UTC_OFFSET_HOURS` | часовой пояс для показа времени | `5` (Казахстан) |
| `SUPPORT_EMAIL`, `SUPPORT_PHONE`, `ORG_NAME` | контакты психологической службы в подвале и на странице экстренной помощи | не показываются |
| `INITIAL_SUPERADMIN_USERNAME`, `INITIAL_SUPERADMIN_PASSWORD`, `INITIAL_SUPERADMIN_EMAIL` | создать первого суперадмина при старте, если его нет | — |

## Команды

```bash
flask --app flask_app create-superadmin <логин> <email>   # создать суперадмина
flask --app flask_app set-password <логин>                 # задать пароль пользователю
flask --app flask_app audit-default-passwords [--apply]    # найти студентов с паролем «логин+abc»
```

`audit-default-passwords --apply` помечает таких студентов: при следующем входе
им придётся задать собственный пароль.

## Развёртывание на PythonAnywhere

1. Сделайте резервную копию `instance/psych_help.db` (Files → Download).
2. Обновите код (`git pull` или загрузка файлов) и выполните `pip install --user -r requirements.txt`.
3. В разделе Web задайте переменные окружения (через WSGI-файл: `os.environ['SECRET_KEY'] = '...'`)
   и включите Force HTTPS; затем `SESSION_COOKIE_SECURE=1`.
4. Reload. При первом старте приложение:
   - добавит новые колонки в базу;
   - исправит текст интерпретации у старых результатов, где он был подставлен ошибочно;
   - сбросит пароли служебных аккаунтов, совпадающие с паролями, которые когда-то лежали в репозитории.
     Задайте новый пароль: `flask --app flask_app set-password <логин>` в Bash-консоли.
5. Выполните `flask --app flask_app audit-default-passwords --apply`.

## Структура

```
flask_app.py   маршруты, инициализация, CLI
admin.py       панель администратора (/admin)
models.py      модели SQLAlchemy
services.py    логика: время, подсчёт тестов и подшкал, встречи, анонимные диалоги, удаление пользователя
security.py    CSRF, ограничение попыток входа, проверка загружаемых картинок
schema.py      добавление недостающих колонок в существующую базу
pdf_utils.py   PDF-отчёты (шрифт DejaVuSans.ttf в корне)
templates/     шаблоны Jinja2
tests/         pytest
```
