import os
import sqlite3
from functools import wraps
from pathlib import Path

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    flash,
    g,
)
from werkzeug.security import generate_password_hash, check_password_hash


BASE_DIR = Path(__file__).resolve().parent
DATABASE = BASE_DIR / "usuarios.db"

app = Flask(__name__)

# En producción, configura SECRET_KEY como variable de entorno.
app.config["SECRET_KEY"] = os.environ.get(
    "SECRET_KEY", "clave-local-solo-para-desarrollo"
)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = (
    os.environ.get("COOKIE_SECURE", "false").lower() == "true"
)


def get_db():
    """Obtiene una conexión SQLite para la petición actual."""
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    """Cierra la conexión al finalizar la petición."""
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    """Crea la tabla de usuarios si todavía no existe."""
    with sqlite3.connect(DATABASE) as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS usuarios (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                nombre TEXT NOT NULL,
                correo TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL
            )
        """)
        db.commit()


def login_required(view):
    """Impide el acceso a páginas privadas sin iniciar sesión."""
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if "usuario_id" not in session:
            flash("Debes iniciar sesión para continuar.", "info")
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped_view


@app.route("/")
def index():
    if "usuario_id" in session:
        return redirect(url_for("inicio"))
    return redirect(url_for("login"))


@app.route("/registro", methods=["GET", "POST"])
def registro():
    if request.method == "POST":
        nombre = request.form.get("nombre", "").strip()
        correo = request.form.get("correo", "").strip().lower()
        password = request.form.get("password", "")
        confirmar = request.form.get("confirmar", "")

        if not nombre or not correo or not password or not confirmar:
            flash("Todos los campos son obligatorios.", "error")
            return render_template("registro.html")

        if len(nombre) > 100 or len(correo) > 254:
            flash("El nombre o el correo son demasiado largos.", "error")
            return render_template("registro.html")

        if "@" not in correo or "." not in correo.rsplit("@", 1)[-1]:
            flash("Introduce un correo electrónico válido.", "error")
            return render_template("registro.html")

        if len(password) < 8:
            flash("La contraseña debe tener al menos 8 caracteres.", "error")
            return render_template("registro.html")

        if password != confirmar:
            flash("Las contraseñas no coinciden.", "error")
            return render_template("registro.html")

        password_hash = generate_password_hash(password)

        try:
            db = get_db()
            db.execute(
                """
                INSERT INTO usuarios (nombre, correo, password_hash)
                VALUES (?, ?, ?)
                """,
                (nombre, correo, password_hash),
            )
            db.commit()
        except sqlite3.IntegrityError:
            flash("Ya existe una cuenta con ese correo.", "error")
            return render_template("registro.html")

        flash("Cuenta creada correctamente. Ya puedes iniciar sesión.", "success")
        return redirect(url_for("login"))

    return render_template("registro.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        correo = request.form.get("correo", "").strip().lower()
        password = request.form.get("password", "")

        db = get_db()
        usuario = db.execute(
            "SELECT * FROM usuarios WHERE correo = ?",
            (correo,),
        ).fetchone()

        if usuario is None or not check_password_hash(
            usuario["password_hash"], password
        ):
            flash("Correo o contraseña incorrectos.", "error")
            return render_template("login.html")

        # Evita conservar datos de una sesión anterior.
        session.clear()
        session["usuario_id"] = usuario["id"]
        session["usuario_nombre"] = usuario["nombre"]

        flash("¡Bienvenido! Has iniciado sesión correctamente.", "success")
        return redirect(url_for("inicio"))

    return render_template("login.html")


@app.route("/inicio")
@login_required
def inicio():
    return render_template(
        "inicio.html",
        nombre=session.get("usuario_nombre", "Usuario"),
    )


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    session.clear()
    flash("Has cerrado sesión correctamente.", "success")
    return redirect(url_for("login"))


# Inicializa la base de datos al arrancar la aplicación.
init_db()


if __name__ == "__main__":
    app.run(debug=os.environ.get("FLASK_DEBUG", "true").lower() == "true")