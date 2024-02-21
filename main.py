from flask import Flask, render_template, request, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
import pyotp
import qrcode
import secrets
import string
import base64

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'  # Путь к базе данных SQLite
app.secret_key = secrets.token_urlsafe(16)  # Генерация секретного ключа для сессий
db = SQLAlchemy(app)


# Модель пользователя
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)
    secret_key = db.Column(db.String(16), nullable=False)


# Генерация случайного ключа для 2FA в формате Base32
def generate_random_secret_key(length=16):
    random_bytes = secrets.token_bytes(length)
    base32_secret = base64.b32encode(random_bytes)
    print(base32_secret.decode('utf-8'))
    return base32_secret.decode('utf-8')


# Страница выбора действия
@app.route('/')
def index():
    return render_template('index.html')


# Страница регистрации (часть 1)
@app.route('/registration')
def registration():
    session['secret_key'] = secrets.token_urlsafe(16)  # Генерация секретного ключа для сессии
    return render_template('registration_part1.html')


# Обработка данных регистрации (часть 1)
@app.route('/register', methods=['POST'])
def register():
    username = request.form['username']
    password = request.form['password']

    # Генерация случайного ключа 2FA
    totp = generate_random_secret_key()

    # Сохранение ключа 2FA в сессии для последующей проверки
    session['registration_totp'] = totp

    # Генерация и сохранение QR-кода
    key_uri = pyotp.totp.TOTP(totp).provisioning_uri(name=username, issuer_name="MyWebSite")
    qrcode.make(key_uri).save(f"static/totp.png")

    return redirect(url_for('registration_part2', username=username, password=password))


# Страница регистрации (часть 2)
@app.route('/registration/part2')
def registration_part2():
    username = request.args.get('username')
    password = request.args.get('password')
    return render_template('registration_part2.html', username=username, password=password)


# Обработка данных регистрации (часть 2)
@app.route('/register/part2', methods=['POST'])
def register_part2():
    totp_input = request.form['totp']

    # Проверка правильности ввода 2FA
    if not pyotp.TOTP(session['registration_totp']).verify(totp_input):
        error_message = "Неверный код 2FA. Пожалуйста, повторите попытку."
        return render_template('registration_part2.html', error=error_message)

    # Создание нового пользователя
    username = request.form['username']
    password = request.form['password']
    user = User(username=username, password=password, secret_key=session.pop('registration_totp'))
    db.session.add(user)
    db.session.commit()

    # Перенаправление на страницу успешной регистрации
    return redirect(url_for('registration_success', username=username))



# Страница успешной регистрации
@app.route('/registration_success/<username>')
def registration_success(username):
    return render_template('registration_success.html', username=username)


# Страница входа
@app.route('/login')
def login():
    return render_template('login.html')


# Обработка данных входа
@app.route('/login', methods=['POST'])
def login_post():
    username = request.form['username']
    password = request.form['password']
    totp = request.form['totp']

    # Проверка учетных данных
    user = User.query.filter_by(username=username, password=password).first()
    if user:
        # Проверка кода 2FA
        if pyotp.TOTP(user.secret_key).verify(totp):
            # Перенаправление на страницу успешного входа
            return redirect(url_for('login_success', username=username))
        else:
            return "Неверный код 2FA"
    else:
        return "Неверное имя пользователя или пароль"


# Страница успешного входа
@app.route('/login_success/<username>')
def login_success(username):
    return render_template('login_success.html', username=username)


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
