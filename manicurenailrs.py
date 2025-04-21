from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    g,
    session,
    make_response,
)
from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    logout_user,
    login_required,
    current_user,
)
import sqlite3
from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    logout_user,
    login_required,
    current_user,
)
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config["SECRET_KEY"] = (
    "caiolindocaiolindo"  # Substitua por uma chave secreta forte!
)

DATABASE = "agendamentos.db"  # Nome do arquivo do banco de dados SQLite

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"  # Define a rota para a página de login


class User(UserMixin):
    def __init__(self, id, username, password):
        self.id = id
        self.username = username
        self.password = password


@login_manager.user_loader
def load_user(user_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT id, username, password FROM users WHERE id = ?", (user_id,))
    user_data = cursor.fetchone()
    if user_data:
        return User(user_data["id"], user_data["username"], user_data["password"])
    return None


def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row  # Para acessar as colunas por nome
    return db


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()


def init_db():
    with app.app_context():
        db = get_db()
        with app.open_resource("schema.sql", mode="r") as f:
            db.cursor().executescript(f.read())
        db.commit()


@app.cli.command("initdb")
def initdb_command():
    """Initializes the database."""
    init_db()
    print("Initializes the database")


@app.cli.command("create-admin")
def create_admin():
    """Creates an admin user."""
    username = input("Digite o nome de usuário do administrador: ")
    password = input("Digite a senha do administrador: ")
    password_hash = generate_password_hash(password)
    db = get_db()
    cursor = db.cursor()
    try:
        cursor.execute(
            "INSERT INTO users (username, password) VALUES (?, ?)",
            (username, password_hash),
        )
        db.commit()
        print(f'Usuário administrador "{username}" criado com sucesso.')
    except sqlite3.IntegrityError:
        print(f'Erro: O nome de usuário "{username}" já existe.')


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/agendar", methods=["GET", "POST"])
def agendar():
    if request.method == "POST":
        nome = request.form["nome"]
        horario = request.form["horario"]
        servico = request.form["servico"]

        horario_dt = datetime.strptime(horario, "%Y-%m-%dT%H:%M")
        horario_formatado = horario_dt.strftime("%d/%m/%Y %H:%M")

        db = get_db()
        cursor = db.cursor()
        cursor.execute(
            "INSERT INTO agendamentos (nome, horario, servico) VALUES (?, ?, ?)",
            (nome, horario_formatado, servico),
        )
        db.commit()

        return redirect(url_for("admin"))
    return render_template("agendar.html")


@app.route("/admin")
@login_required
def admin():
    db = get_db()
    cursor = db.cursor()
    cursor.execute(
        "SELECT id, nome, horario, servico FROM agendamentos ORDER BY horario DESC"
    )
    agendamentos_db = cursor.fetchall()
    return render_template("admin.html", agendamentos=agendamentos_db)


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("admin"))  # Se já estiver logado, redireciona para a página admin

    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        db = get_db()
        cursor = db.cursor()
        cursor.execute(
            "SELECT id, username, password FROM users WHERE username = ?", (username,)
        )
        user_data = cursor.fetchone()

        if user_data and check_password_hash(user_data["password"], password):
            user = User(user_data["id"], user_data["username"], user_data["password"])
            login_user(user)
            next_page = request.args.get("next")  # Pega o 'next' se existir, para redirecionar corretamente após login
            return redirect(next_page or url_for("admin"))  # Se 'next' não existir, vai para a página admin
        else:
            return render_template(
                "login.html", error="Nome de usuário ou senha incorretos."
            )
    return render_template("login.html")


# Login temporario
@app.route("/criar-admin")
def criar_admin():
    username = "michelesouza.mk@hotmail.com"  # Nome do admin
    password = "88393864"  # Senha do admin
    password_hash = generate_password_hash(password)
    db = get_db()
    cursor = db.cursor()
    try:
        cursor.execute(
            "INSERT INTO users (username, password) VALUES (?, ?)",
            (username, password_hash),
        )
        db.commit()
        return f'Usuário administrador "{username}" criado com sucesso.'
    except sqlite3.IntegrityError:
        return f'Erro: O nome de usuário "{username}" já existe.'
    
# Conta quantos admins
@app.route("/contar-admins")
@login_required
def contar_admins():
    # Verifica se o usuário logado é o admin
    if current_user.username != 'admin':
        return "Você não tem permissão para acessar esta página."

    db = get_db()
    cursor = db.cursor()
    
    # Conta quantos usuários têm o nome 'admin'
    cursor.execute("SELECT COUNT(*) FROM users WHERE username = ?", ('admin',))
    count = cursor.fetchone()[0]
    
    return f"Há {count} usuários com o nome 'admin'."


@app.route("/deletar-usuario/<int:user_id>")
@login_required
def deletar_usuario(user_id):
    # Verifica se o usuário logado é o admin, para segurança
    if current_user.username != 'admin':
        return "Você não tem permissão para deletar usuários."

    db = get_db()
    cursor = db.cursor()
    
    # Deleta o usuário pelo ID
    try:
        cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
        db.commit()
        return f"Usuário de ID {user_id} deletado com sucesso."
    except sqlite3.Error as e:
        return f"Erro ao deletar o usuário: {e}"


@app.route("/logout")
@login_required
def logout():
    logout_user()
    session.pop("_user_id", None)
    session.pop("remember_token", None)  # Se você estiver usando "remember me"
    session.modified = True
    session.clear()
    resp = make_response(redirect(url_for("home")))
    resp.delete_cookie("session")  # Tenta deletar o cookie pelo nome
    return resp


if __name__ == "__main__":
    app.run(debug=True)