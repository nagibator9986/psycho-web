"""
PDF-документы: отчёт о студенте, протокол встречи, сводка результатов теста.

Шрифт DejaVuSans лежит в корне проекта (кириллица и казахские буквы),
поэтому генерация не зависит от шрифтов сервера. Текст в ячейках таблиц
оборачивается в Paragraph, чтобы длинные ответы переносились, а не уезжали
за край страницы.
"""
import io
import os

from markupsafe import escape
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

FONT_NAME = 'DejaVuSans'
_FONT_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'DejaVuSans.ttf')


def _styles():
    if FONT_NAME not in pdfmetrics.getRegisteredFontNames():
        pdfmetrics.registerFont(TTFont(FONT_NAME, _FONT_PATH))
    base = getSampleStyleSheet()
    return {
        'title': ParagraphStyle('T', parent=base['Title'], fontName=FONT_NAME, fontSize=16, leading=20),
        'h': ParagraphStyle('H', parent=base['Heading3'], fontName=FONT_NAME),
        'p': ParagraphStyle('P', parent=base['BodyText'], fontName=FONT_NAME, fontSize=9.5, leading=12),
        'cell': ParagraphStyle('C', parent=base['BodyText'], fontName=FONT_NAME, fontSize=8.5, leading=10.5),
        'head': ParagraphStyle('HC', parent=base['BodyText'], fontName=FONT_NAME, fontSize=9,
                               leading=11, textColor=colors.white),
    }


def _para(text, style):
    """Экранирует текст (Paragraph понимает разметку) и сохраняет переносы строк."""
    safe = str(escape('' if text is None else str(text))).replace('\n', '<br/>')
    return Paragraph(safe or '—', style)


def _table(rows, col_widths, styles, header=True):
    data = []
    for i, row in enumerate(rows):
        style = styles['head'] if header and i == 0 else styles['cell']
        data.append([_para(cell, style) for cell in row])
    table = Table(data, colWidths=col_widths, repeatRows=1 if header else 0)
    commands = [
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#94a3b8')),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('LEFTPADDING', (0, 0), (-1, -1), 4),
        ('RIGHTPADDING', (0, 0), (-1, -1), 4),
    ]
    if header:
        commands.append(('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#4f46e5')))
    table.setStyle(TableStyle(commands))
    return table


def _build(elements, pagesize=A4) -> io.BytesIO:
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=pagesize,
        leftMargin=15 * mm, rightMargin=15 * mm, topMargin=15 * mm, bottomMargin=15 * mm,
    )
    doc.build(elements)
    buffer.seek(0)
    return buffer


def _kv_document(title, rows) -> io.BytesIO:
    s = _styles()
    width = A4[0] - 30 * mm
    elements = [
        _para(title, s['title']),
        Spacer(1, 8),
        _table([['Параметр', 'Описание']] + rows, [width * 0.3, width * 0.7], s),
    ]
    return _build(elements)


def student_report_pdf(report, student, psychologist, created_local) -> io.BytesIO:
    na = 'Не указано'
    rows = [
        ['Студент', student.display_name if student else na],
        ['Группа', student.group.name if student and student.group else na],
        ['Дата создания', created_local.strftime('%d.%m.%Y %H:%M') if created_local else na],
        ['Психолог', psychologist.display_name if psychologist else na],
        ['Учебная успеваемость', report.academic_performance or na],
        ['Эмоциональное состояние', report.emotional_state or na],
        ['Социальное взаимодействие', report.social_interaction or na],
        ['Уровень стресса', report.stress_level or na],
        ['Качество сна', report.sleep_quality or na],
        ['Мотивация', report.motivation or na],
        ['Поведенческие паттерны', report.behavior_patterns or na],
        ['Рекомендации', report.recommendations or na],
        ['Дополнительные заметки', report.additional_notes or na],
    ]
    name = student.display_name if student else 'студент'
    return _kv_document(f'Отчёт о студенте: {name}', rows)


def protocol_pdf(protocol, student, psychologist) -> io.BytesIO:
    na = 'Не указано'
    rows = [
        ['Студент', student.display_name if student else na],
        ['Дата встречи', protocol.session_date.strftime('%d.%m.%Y %H:%M') if protocol.session_date else na],
        ['Психолог', psychologist.display_name if psychologist else na],
        ['Продолжительность (мин)', protocol.duration if protocol.duration else na],
        ['Обсуждаемые темы', protocol.topics_discussed or na],
        ['Эмоциональное состояние', protocol.emotional_state or na],
        ['Заметки о прогрессе', protocol.progress_notes or na],
        ['Рекомендации', protocol.recommendations or na],
        ['Домашнее задание', protocol.homework or na],
        ['Дополнительные комментарии', protocol.additional_comments or na],
    ]
    name = student.display_name if student else 'студент'
    return _kv_document(f'Протокол встречи: {name}', rows)


def test_results_pdf(test_title, grouped_rows) -> io.BytesIO:
    """
    grouped_rows: [(название группы, [(ФИО, логин, дата, балл, интерпретация), ...]), ...]
    """
    s = _styles()
    pagesize = landscape(A4)
    width = pagesize[0] - 30 * mm
    widths = [width * 0.22, width * 0.13, width * 0.11, width * 0.07, width * 0.47]

    elements = [_para(f'Результаты теста: {test_title}', s['title']), Spacer(1, 8)]
    total = sum(len(rows) for _, rows in grouped_rows)
    elements.append(_para(f'Всего результатов: {total}', s['p']))
    elements.append(Spacer(1, 8))

    if not grouped_rows:
        elements.append(_para('Тест ещё никто не прошёл.', s['p']))

    for group_name, rows in grouped_rows:
        elements.append(_para(f'Группа: {group_name} ({len(rows)})', s['h']))
        elements.append(Spacer(1, 4))
        table_rows = [['ФИО', 'Логин', 'Дата', 'Балл', 'Интерпретация']] + [list(r) for r in rows]
        elements.append(_table(table_rows, widths, s))
        elements.append(Spacer(1, 10))

    return _build(elements, pagesize=pagesize)
