# create_superadmin.py
from flask_app import app          # берём уже сконфигурированный Flask app
from extensions import db
from models import User
from werkzeug.security import generate_password_hash

username = "super"
email = "super@example.com"
password = "changeme123"

with app.app_context():
    if User.query.filter((User.username == username) | (User.email == email)).first():
        print("Пользователь уже существует – пропускаю.")
    else:
        u = User(
            username=username,
            email=email,
            password=generate_password_hash(password),
            role='superadmin',
            full_name='Super Admin'
        )
        db.session.add(u)
        db.session.commit()
        print("Суперадмин создан:", username, email)
