from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    g,
    session,
    make_response,
    flash,
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
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os

# Inicialização do Flask
app = Flask(__name__)

# Usar variável de ambiente para a chave secreta 
# Em produção, use uma chave forte e guarde em variável de ambiente
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "chave_temporaria_para_desenvolvimento")

# Função para conectar ao banco de dados
def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

DATABASE = "agendamentos.db"  # Nome do arquivo do banco de dados SQLite

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"  # Define a rota para a página de login


class User(UserMixin):
    def __init__(self, id, username, password, role='user'):
        self.id = id
        self.username = username
        self.password = password
        self.role = role  # Adicionando um campo de role para controle de acesso
    
    def is_admin(self):
        return self.role == 'admin'


@login_manager.user_loader
def load_user(user_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT id, username, password, role FROM users WHERE id = ?", (user_id,))
    user_data = cursor.fetchone()
    if user_data:
        return User(
            user_data["id"], 
            user_data["username"], 
            user_data["password"],
            user_data.get("role", "user")  # Definir "user" como padrão 
        )
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
    print("Banco de dados inicializado com sucesso.")


@app.cli.command("create-admin")
def create_admin():
    """Creates an admin user."""
    username = input("Digite o nome de usuário do administrador: ")
    password = input("Digite a senha do administrador: ")
    password_hash = generate_password_hash(password)
    db = get_db()
    cursor = db.cursor()
    try:
        # Adicionando campo role='admin'
        cursor.execute(
            "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
            (username, password_hash, "admin"),
        )
        db.commit()
        print(f'Usuário administrador "{username}" criado com sucesso.')
    except sqlite3.IntegrityError:
        print(f'Erro: O nome de usuário "{username}" já existe.')


# Função auxiliar para verificar se o banco de dados existe
def check_database():
    if not os.path.exists(DATABASE):
        init_db()
        # Criar um usuário admin padrão se não existir nenhum
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT COUNT(*) FROM users WHERE role = 'admin'")
        count = cursor.fetchone()[0]
        if count == 0:
            # Criar usuário admin padrão (admin/admin123)
            password_hash = generate_password_hash("admin123")
            cursor.execute(
                "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                ("admin", password_hash, "admin"),
            )
            db.commit()
            print("Usuário admin padrão criado (username: admin, senha: admin123)")


with app.app_context():
    # Verificar banco de dados na inicialização
    check_database()


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/agendar", methods=["GET", "POST"])
def agendar():
    # Obter serviços disponíveis do banco de dados
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT id, nome, descricao, duracao, preco FROM servico WHERE disponivel = 1")
    servico = cursor.fetchall()
    
    if request.method == "POST":
        # Validação básica dos dados de entrada
        nome = request.form.get("nome", "").strip()
        horario = request.form.get("horario", "").strip()
        servico = request.form.get("servico", "").strip()
        
        # Validação dos campos
        if not nome or not horario or not servico:
            return render_template("agendar.html", error="Todos os campos são obrigatórios.", servicos=servicos)
        
        try:
            # Validação do formato de data/hora
            horario_dt = datetime.strptime(horario, "%Y-%m-%dT%H:%M")
            
            # Verifica se o horário não está no passado
            if horario_dt < datetime.now():
                return render_template("agendar.html", 
                                     error="Não é possível agendar para uma data no passado.",
                                     servicos=servicos)
                
            # Armazenar em formato ISO para facilitar ordenação no banco
            horario_iso = horario_dt.isoformat()
            
            cursor.execute(
                "INSERT INTO agendamentos (nome, horario, servico) VALUES (?, ?, ?)",
                (nome, horario_iso, servico),
            )
            db.commit()
            
            return redirect(url_for("home", success="Agendamento realizado com sucesso!"))
        except ValueError:
            return render_template("agendar.html", error="Formato de data/hora inválido.", servicos=servicos)
        
    return render_template("agendar.html", servicos=servicos)


@app.route("/admin")
@login_required
def admin():
    # Verifica se o usuário tem permissão de admin
    if not current_user.is_admin():
        flash("Você não tem permissão para acessar esta página.", "error")
        return redirect(url_for("home"))
        
    db = get_db()
    cursor = db.cursor()
    
    # Buscar os agendamentos
    cursor.execute(
        "SELECT id, nome, horario, servico FROM agendamentos ORDER BY horario DESC"
    )
    agendamentos_db = cursor.fetchall()
    
    # Formatar a data para exibição
    agendamentos = []
    for agendamento in agendamentos_db:
        try:
            horario_dt = datetime.fromisoformat(agendamento["horario"])
            horario_formatado = horario_dt.strftime("%d/%m/%Y %H:%M")
        except (ValueError, TypeError):
            # Caso o formato não seja o esperado, mantém o original
            horario_formatado = agendamento["horario"]
            
        agendamentos.append({
            "id": agendamento["id"],
            "nome": agendamento["nome"],
            "horario": horario_formatado,
            "servico": agendamento["servico"]
        })
    
    # Buscar os serviços
    cursor.execute("SELECT id, nome, descricao, duracao, preco, disponivel FROM servicos")
    servicos = cursor.fetchall()
        
    return render_template("admin.html", agendamentos=agendamentos, servicos=servicos)


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        if current_user.is_admin():
            return redirect(url_for("admin"))
        return redirect(url_for("home"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        
        # Validação básica
        if not username or not password:
            return render_template("login.html", error="Preencha todos os campos.")
            
        db = get_db()
        cursor = db.cursor()
        cursor.execute(
            "SELECT id, username, password, role FROM users WHERE username = ?", (username,)
        )
        user_data = cursor.fetchone()

        if user_data and check_password_hash(user_data["password"], password):
            user = User(
                user_data["id"], 
                user_data["username"], 
                user_data["password"],
                user_data.get("role", "user")
            )
            login_user(user)
            next_page = request.args.get("next")
            
            # Redireciona com base no papel do usuário
            if user.is_admin() and not next_page:
                return redirect(url_for("admin"))
            return redirect(next_page or url_for("home"))
        else:
            return render_template(
                "login.html", error="Nome de usuário ou senha incorretos."
            )
    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    session.pop("_user_id", None)
    session.pop("remember_token", None)
    session.modified = True
    session.clear()
    resp = make_response(redirect(url_for("home")))
    resp.delete_cookie("session")
    return resp


# Novas rotas para gerenciamento de serviços
@app.route("/admin/servicos")
@login_required
def admin_servicos():
    if not current_user.is_admin():
        flash("Você não tem permissão para acessar esta página.", "error")
        return redirect(url_for("home"))
        
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT id, nome, descricao, duracao, preco, disponivel FROM servicos ORDER BY nome")
    servicos = cursor.fetchall()
    
    return render_template("admin_servicos.html", servicos=servicos)


@app.route("/admin/servicos/novo", methods=["GET", "POST"])
@login_required
def novo_servico():
    if not current_user.is_admin():
        flash("Você não tem permissão para acessar esta página.", "error")
        return redirect(url_for("home"))
        
    if request.method == "POST":
        nome = request.form.get("nome", "").strip()
        descricao = request.form.get("descricao", "").strip()
        duracao = request.form.get("duracao", "").strip()
        preco = request.form.get("preco", "").strip()
        disponivel = 1 if request.form.get("disponivel") else 0
        
        # Validação básica
        if not nome or not duracao or not preco:
            flash("Nome, duração e preço são campos obrigatórios.", "error")
            return render_template("novo_servico.html")
            
        try:
            duracao = int(duracao)
            preco = float(preco)
            
            db = get_db()
            cursor = db.cursor()
            cursor.execute(
                "INSERT INTO servicos (nome, descricao, duracao, preco, disponivel) VALUES (?, ?, ?, ?, ?)",
                (nome, descricao, duracao, preco, disponivel)
            )
            db.commit()
            
            flash("Serviço adicionado com sucesso!", "success")
            return redirect(url_for("admin_servicos"))
        except ValueError:
            flash("Duração deve ser um número inteiro e preço deve ser um valor decimal.", "error")
            return render_template("novo_servico.html")
            
    return render_template("novo_servico.html")


@app.route("/admin/servicos/editar/<int:id>", methods=["GET", "POST"])
@login_required
def editar_servico(id):
    if not current_user.is_admin():
        flash("Você não tem permissão para acessar esta página.", "error")
        return redirect(url_for("home"))
        
    db = get_db()
    cursor = db.cursor()
    
    if request.method == "POST":
        nome = request.form.get("nome", "").strip()
        descricao = request.form.get("descricao", "").strip()
        duracao = request.form.get("duracao", "").strip()
        preco = request.form.get("preco", "").strip()
        disponivel = 1 if request.form.get("disponivel") else 0
        
        # Validação básica
        if not nome or not duracao or not preco:
            flash("Nome, duração e preço são campos obrigatórios.", "error")
            cursor.execute("SELECT * FROM servicos WHERE id = ?", (id,))
            servico = cursor.fetchone()
            return render_template("editar_servico.html", servico=servico)
            
        try:
            duracao = int(duracao)
            preco = float(preco)
            
            cursor.execute(
                "UPDATE servicos SET nome = ?, descricao = ?, duracao = ?, preco = ?, disponivel = ? WHERE id = ?",
                (nome, descricao, duracao, preco, disponivel, id)
            )
            db.commit()
            
            flash("Serviço atualizado com sucesso!", "success")
            return redirect(url_for("admin_servicos"))
        except ValueError:
            flash("Duração deve ser um número inteiro e preço deve ser um valor decimal.", "error")
            cursor.execute("SELECT * FROM servicos WHERE id = ?", (id,))
            servico = cursor.fetchone()
            return render_template("editar_servico.html", servico=servico)
    
    # GET - Carregar dados do serviço para edição
    cursor.execute("SELECT * FROM servicos WHERE id = ?", (id,))
    servico = cursor.fetchone()
    
    if not servico:
        flash("Serviço não encontrado.", "error")
        return redirect(url_for("admin_servicos"))
        
    return render_template("editar_servico.html", servico=servico)


@app.route("/admin/servicos/excluir/<int:id>")
@login_required
def excluir_servico(id):
    if not current_user.is_admin():
        flash("Você não tem permissão para acessar esta página.", "error")
        return redirect(url_for("home"))
        
    db = get_db()
    cursor = db.cursor()
    
    # Verificar se o serviço está sendo utilizado em agendamentos
    cursor.execute("SELECT COUNT(*) FROM agendamentos WHERE servico = (SELECT nome FROM servicos WHERE id = ?)", (id,))
    count = cursor.fetchone()[0]
    
    if count > 0:
        flash(f"Este serviço não pode ser excluído pois está sendo utilizado em {count} agendamento(s).", "error")
        return redirect(url_for("admin_servicos"))
    
    # Excluir o serviço
    cursor.execute("DELETE FROM servicos WHERE id = ?", (id,))
    db.commit()
    
    flash("Serviço excluído com sucesso!", "success")
    return redirect(url_for("admin_servicos"))


@app.route("/admin/agendamentos/excluir/<int:id>")
@login_required
def excluir_agendamento(id):
    if not current_user.is_admin():
        flash("Você não tem permissão para acessar esta página.", "error")
        return redirect(url_for("home"))
        
    db = get_db()
    cursor = db.cursor()
    cursor.execute("DELETE FROM agendamentos WHERE id = ?", (id,))
    db.commit()
    
    flash("Agendamento excluído com sucesso!", "success")
    return redirect(url_for("admin"))


if __name__ == "__main__":
    # Em ambiente de produção, use:
    # app.run(host='0.0.0.0', debug=False)
    app.run(debug=True)  # Use apenas em desenvolvimento