"""
Лёгкая миграция схемы без Alembic.

db.create_all() создаёт только отсутствующие таблицы, но не добавляет новые
колонки в существующие. Здесь — список колонок, которые появлялись в моделях
со временем; недостающие добавляются через ALTER TABLE (операция аддитивная,
данные не трогает).
"""
from sqlalchemy import inspect, text
from sqlalchemy.exc import OperationalError

from extensions import db

# (таблица, колонка, SQL-определение)
COLUMNS = [
    ('user', 'group_id', 'INTEGER'),
    ('user', 'must_change_password', 'BOOLEAN NOT NULL DEFAULT 0'),
    ('user', 'privacy_accepted_at', 'DATETIME'),
    ('post', 'is_anonymous', 'BOOLEAN NOT NULL DEFAULT 0'),
    ('test', 'title_kk', 'VARCHAR(200)'),
    ('test', 'description_kk', 'TEXT'),
    ('test', 'test_type', "VARCHAR(20) DEFAULT 'classic'"),
    ('question', 'text_kk', 'TEXT'),
    ('question_option', 'text_kk', 'VARCHAR(200)'),
    ('test_result', 'language', 'VARCHAR(5)'),
    ('test_interpretation', 'is_alert', 'BOOLEAN NOT NULL DEFAULT 0'),
]


def ensure_schema() -> list[str]:
    """Создаёт недостающие таблицы и колонки. Возвращает список добавленного."""
    db.create_all()

    inspector = inspect(db.engine)
    tables = set(inspector.get_table_names())
    added = []

    with db.engine.begin() as conn:
        for table, column, ddl in COLUMNS:
            if table not in tables:
                continue
            existing = {c['name'] for c in inspector.get_columns(table)}
            if column in existing:
                continue
            try:
                with conn.begin_nested():
                    conn.execute(text(f'ALTER TABLE "{table}" ADD COLUMN "{column}" {ddl}'))
            except OperationalError as e:
                # колонку успел добавить другой процесс, стартовавший одновременно
                if 'duplicate column' not in str(e).lower():
                    raise
                continue
            added.append(f'{table}.{column}')

        # У старых тестов тип мог остаться пустым
        if 'test' in tables:
            conn.execute(text("UPDATE test SET test_type = 'classic' WHERE test_type IS NULL OR test_type = ''"))

    return added
