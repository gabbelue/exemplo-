from flask import Flask, render_template, redirect, url_for, request
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required

app = Flask(__name__)
app.config.from_object('config.Config')

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Modelos de Usuário e Exercício
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    matricula = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    senha = db.Column(db.String(60), nullable=False)
    exercises = db.relationship('Exercise', backref='author', lazy=True)

class Exercise(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100), nullable=False)
    descricao = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Rota para cadastro de usuários
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        matricula = request.form['matricula']
        email = request.form['email']
        senha = bcrypt.generate_password_hash(request.form['senha']).decode('utf-8')

        # Verifica se o usuário já existe com essa matrícula
        user_exists = User.query.filter_by(matricula=matricula).first()
        if user_exists:
            return "Usuário já cadastrado com essa matrícula!"

        novo_usuario = User(matricula=matricula, email=email, senha=senha)
        db.session.add(novo_usuario)
        db.session.commit()

        return redirect(url_for('login'))  # Redireciona para a página de login
    return render_template('register.html')

# Rota para login de usuários
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        matricula = request.form['matricula']
        senha = request.form['senha']
        user = User.query.filter_by(matricula=matricula).first()

        # Verifica se a matrícula e a senha estão corretas
        if user and bcrypt.check_password_hash(user.senha, senha):
            login_user(user)
            return redirect(url_for('dashboard'))  # Redireciona para o dashboard
        else:
            return "Matrícula ou senha inválida!"

    return render_template('login.html')

# Rota para logout de usuários
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))
# Rota para o dashboard (área protegida)
@app.route('/dashboard')
@login_required
def dashboard():
    return f"Bem-vindo, {current_user.matricula}! <br><a href='/logout'>Logout</a>"

# Rota para cadastro de exercícios físicos (apenas usuários logados)
@app.route('/add_exercise', methods=['GET', 'POST'])
@login_required
def add_exercise():
    if request.method == 'POST':
        nome_exercicio = request.form['nome_exercicio']
        descricao = request.form['descricao']

        novo_exercicio = Exercise(nome=nome_exercicio, descricao=descricao, user_id=current_user.id)
        db.session.add(novo_exercicio)
        db.session.commit()

        return redirect(url_for('dashboard'))

    return render_template('add_exercise.html')

if __name__ == '__main__':
    app.run(debug=True)

