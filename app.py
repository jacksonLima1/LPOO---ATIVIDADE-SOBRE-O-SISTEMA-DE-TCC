import os
from typing import Optional, Tuple
from flask import (
    Flask, render_template, redirect, url_for,
    flash, request, send_from_directory, abort
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, login_user, logout_user,
    login_required, current_user, UserMixin
)
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, Length
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

# =========================================================
# GLOBAL EXTENSIONS
# =========================================================

db = SQLAlchemy()
login_manager = LoginManager()
login_manager.login_view = 'login'


# =========================================================
# CONFIG
# =========================================================

class AppConfig:
    BASE_DIR = os.path.abspath(os.path.dirname(__file__))
    UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
    SECRET_KEY = os.getenv('SECRET_KEY', 'troque_essa_chave')
    SQLALCHEMY_DATABASE_URI = os.getenv(
        'DATABASE_URI', f"sqlite:///{os.path.join(BASE_DIR, 'tcc.db')}"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024
    ALLOWED_EXTENSIONS = {'pdf'}


# =========================================================
# APP FACTORY (OOP)
# =========================================================

class TCCApp:
    def __init__(self):
        self.app = Flask(__name__)
        self.app.config.from_object(AppConfig)

        os.makedirs(AppConfig.UPLOAD_FOLDER, exist_ok=True)

        db.init_app(self.app)
        login_manager.init_app(self.app)


# =========================================================
# MODELS
# =========================================================

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    cpf = db.Column(db.String(20), unique=True, nullable=False)
    nascimento = db.Column(db.String(20), nullable=False)
    curso_id = db.Column(db.Integer, db.ForeignKey('curso.id'), nullable=True)
    senha_hash = db.Column(db.String(200), nullable=False)

    def set_password(self, senha: str) -> None:
        self.senha_hash = generate_password_hash(senha)

    def check_password(self, senha: str) -> bool:
        return check_password_hash(self.senha_hash, senha)


class TCC(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    titulo = db.Column(db.String(250), nullable=False)
    filename = db.Column(db.String(250), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref='tccs', lazy=True)  # ← ESSA É A CORREÇÃO
    orientador_id = db.Column(db.Integer, db.ForeignKey('orientador.id'), nullable=True)

# =========================================================
# NOVOS MODELS (ADICIONAR ABAIXO)
# =========================================================

class Curso(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(150), unique=True, nullable=False)

    # Relacionamento 1:N com usuários
    users = db.relationship('User', backref='curso_rel', lazy=True)


class Orientador(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)

    # Relacionamento 1:N com TCC
    tccs = db.relationship('TCC', backref='orientador_rel', lazy=True)


class Download(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    tcc_id = db.Column(db.Integer, db.ForeignKey('tcc.id'), nullable=False)
    data_download = db.Column(db.DateTime, server_default=db.func.now())

    # Relacionamentos
    user = db.relationship('User', backref='downloads')
    tcc = db.relationship('TCC', backref='downloads')


# =========================================================
# SERVICES
# =========================================================

class UserService:
    @staticmethod
    def create_user(form) -> User:
        user = User(
            nome=form.nome.data,
            email=form.email.data,
            cpf=form.cpf.data,
            nascimento=form.nascimento.data,
            curso_id=form.curso.data
        )
        user.set_password(form.senha.data)
        db.session.add(user)
        db.session.commit()
        return user

    @staticmethod
    def authenticate(email: str, senha: str) -> Optional[User]:
        user = User.query.filter_by(email=email).first()
        if user and user.check_password(senha):
            return user
        return None


class UploadService:
    @staticmethod
    def allowed_file(filename: str) -> bool:
        return '.' in filename and filename.rsplit('.', 1)[1].lower() in AppConfig.ALLOWED_EXTENSIONS

    @staticmethod
    def save(file, user_id: int) -> Tuple[bool, str]:
        if not file or file.filename == '':
            return False, 'Nenhum arquivo selecionado'

        if not UploadService.allowed_file(file.filename):
            return False, 'Apenas arquivos PDF são permitidos'

        filename = secure_filename(file.filename)
        filename_on_disk = f"{user_id}_{filename}"
        path = os.path.join(AppConfig.UPLOAD_FOLDER, filename_on_disk)
        file.save(path)

        return True, filename_on_disk


# =========================================================
# FORMS
# =========================================================

class RegisterForm(FlaskForm):
    nome = StringField('Nome', validators=[DataRequired(), Length(max=150)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    cpf = StringField('CPF', validators=[DataRequired()])
    nascimento = StringField('Nascimento', validators=[DataRequired()])
    curso = StringField('Curso', validators=[DataRequired()])
    senha = PasswordField('Senha', validators=[DataRequired(), Length(min=6)])
    submit = SubmitField('Cadastrar')


class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    senha = PasswordField('Senha', validators=[DataRequired()])
    submit = SubmitField('Entrar')


class UploadForm(FlaskForm):
    titulo = StringField('Título', validators=[DataRequired()])
    submit = SubmitField('Enviar')


# =========================================================
# LOGIN LOADER
# =========================================================

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# =========================================================
# ROUTES
# =========================================================

def register_routes(app: Flask):

    @app.route('/')
    def index():
        return render_template('index.html')

    @app.route('/register', methods=['GET', 'POST'])
    def register():
        form = RegisterForm()
        if form.validate_on_submit():

            if User.query.filter_by(email=form.email.data).first():
                flash('Email já existe', 'warning')
                return redirect(url_for('register'))

            if User.query.filter_by(cpf=form.cpf.data).first():
                flash('CPF já existe', 'warning')
                return redirect(url_for('register'))

            UserService.create_user(form)
            flash('Cadastro realizado com sucesso.', 'success')
            return redirect(url_for('login'))

        return render_template('register.html', form=form)

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        form = LoginForm()
        if form.validate_on_submit():
            user = UserService.authenticate(form.email.data, form.senha.data)
            if user:
                login_user(user)
                flash('Login realizado.', 'success')
                return redirect(url_for('dashboard'))
            flash('Credenciais inválidas', 'danger')

        return render_template('login.html', form=form)

    @app.route('/logout')
    @login_required
    def logout():
        logout_user()
        flash('Logout realizado.', 'info')
        return redirect(url_for('index'))

    @app.route('/dashboard')
    @login_required
    def dashboard():
        tccs = TCC.query.filter_by(user_id=current_user.id).all()
        return render_template('dashboard.html', tccs=tccs)

    @app.route('/upload', methods=['GET', 'POST'])
    @login_required
    def upload():
        form = UploadForm()
        if request.method == 'POST':
            file = request.files.get('arquivo')

            ok, result = UploadService.save(file, current_user.id)
            if not ok:
                flash(result, 'danger')
                return redirect(request.url)

            tcc = TCC(
                titulo=form.titulo.data,
                filename=result,
                user_id=current_user.id
            )
            db.session.add(tcc)
            db.session.commit()

            flash('TCC enviado com sucesso!', 'success')
            return redirect(url_for('dashboard'))

        return render_template('upload.html', form=form)

    @app.route('/download/<int:tcc_id>')
    @login_required
    def download(tcc_id):
        tcc = TCC.query.get_or_404(tcc_id)
        if tcc.user_id != current_user.id:
            abort(403)
        return send_from_directory(AppConfig.UPLOAD_FOLDER, tcc.filename, as_attachment=True)

    @app.route('/tccs')
    def tccs_publicos():
        tccs = TCC.query.all()
        return render_template('tccs_publicos.html', tccs=tccs)

    @app.route('/tccs/download/<int:tcc_id>')
    def download_publico(tcc_id):
        tcc = TCC.query.get_or_404(tcc_id)
        return send_from_directory(AppConfig.UPLOAD_FOLDER, tcc.filename, as_attachment=True)


# =========================================================
# START
# =========================================================

tcc_app = TCCApp()
app = tcc_app.app
register_routes(app)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()

    app.run(debug=True)

