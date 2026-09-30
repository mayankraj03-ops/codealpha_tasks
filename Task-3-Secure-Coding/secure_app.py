from flask import Flask, request, render_template_string
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import subprocess
import os
import ipaddress
import re

app = Flask(__name__)

# Load the Flask secret from an environment variable.
# The fallback is intended only for local educational testing.
app.config["SECRET_KEY"] = os.environ.get(
    "SECRET_KEY",
    "local-development-secret"
)

DATABASE = "users.db"


def get_db():
    """Create a connection to the local SQLite database."""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Create the users table and a local demonstration account."""
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    """)

    # Create a demonstration account only if it does not already exist.
    # The password is hashed before being stored.
    cursor.execute(
        "SELECT id FROM users WHERE username = ?",
        ("demo_user",)
    )

    if cursor.fetchone() is None:
        password_hash = generate_password_hash("DemoPass123!")

        cursor.execute(
            """
            INSERT INTO users (username, password)
            VALUES (?, ?)
            """,
            ("demo_user", password_hash)
        )

    conn.commit()
    conn.close()


@app.route("/login", methods=["GET", "POST"])
def login():
    """Authenticate a user using a parameterized SQL query."""
    message = ""

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        # Basic input validation.
        if not re.fullmatch(r"[A-Za-z0-9_.-]{3,30}", username):
            message = "Invalid username or password."
        elif not password:
            message = "Invalid username or password."
        else:
            conn = get_db()

            try:
                cursor = conn.cursor()

                # Parameterized query prevents SQL injection.
                cursor.execute(
                    """
                    SELECT username, password
                    FROM users
                    WHERE username = ?
                    """,
                    (username,)
                )

                user = cursor.fetchone()

            finally:
                conn.close()

            if user and check_password_hash(
                user["password"],
                password
            ):
                message = "Login successful!"
            else:
                # Do not reveal whether the username exists.
                message = "Invalid username or password."

    return render_template_string("""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SecureVault | Secure Login</title>

    <style>
        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
            font-family: Arial, sans-serif;
        }

        body {
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            background:
                radial-gradient(
                    circle at 20% 20%,
                    rgba(0, 255, 170, 0.12),
                    transparent 30%
                ),
                radial-gradient(
                    circle at 80% 80%,
                    rgba(0, 120, 255, 0.12),
                    transparent 30%
                ),
                #050b12;
            color: white;
        }

        .card {
            width: 460px;
            max-width: 92%;
            padding: 45px;
            background: rgba(10, 20, 30, 0.92);
            border: 1px solid rgba(0, 255, 170, 0.2);
            border-radius: 20px;
            box-shadow: 0 25px 70px rgba(0, 0, 0, 0.6);
        }

        h1 {
            margin-bottom: 10px;
        }

        .subtitle {
            color: #91a1b2;
            margin-bottom: 30px;
        }

        label {
            display: block;
            margin-bottom: 8px;
            color: #b7c3cf;
        }

        input {
            width: 100%;
            padding: 13px;
            margin-bottom: 18px;
            border-radius: 8px;
            border: 1px solid #334452;
            background: #0b151f;
            color: white;
        }

        button {
            width: 100%;
            padding: 13px;
            border: 0;
            border-radius: 8px;
            background: #00ffaa;
            color: #03110c;
            font-weight: bold;
            cursor: pointer;
        }

        .message {
            margin-top: 20px;
            padding: 12px;
            border-radius: 8px;
            background: rgba(0, 255, 170, 0.08);
            color: #9ff0d0;
        }

        .links {
            margin-top: 25px;
            line-height: 1.8;
        }

        .links a {
            color: #00ffaa;
            text-decoration: none;
        }
    </style>
</head>

<body>

<div class="card">

    <h1>Secure<span style="color:#00ffaa;">Vault</span></h1>

    <p class="subtitle">
        Secure Coding Demonstration
    </p>

    <form method="POST">

        <label for="username">Username</label>
        <input
            id="username"
            name="username"
            type="text"
            maxlength="30"
            required
        >

        <label for="password">Password</label>
        <input
            id="password"
            name="password"
            type="password"
            required
        >

        <button type="submit">
            Login Securely
        </button>

    </form>

    {% if message %}
        <div class="message">
            {{ message }}
        </div>
    {% endif %}

    <div class="links">
        <a href="/ping?host=127.0.0.1">
            Test secure ping
        </a>
        <br>
        <a href="/search?q=security">
            Test safe search
        </a>
    </div>

</div>

</body>
</html>
""", message=message)


@app.route("/ping")
def ping():
    """Safely execute a local ping without shell interpretation."""

    host = request.args.get("host", "127.0.0.1").strip()

    # Accept either a valid IP address or a simple hostname.
    try:
        ipaddress.ip_address(host)
        valid_host = True
    except ValueError:
        valid_host = bool(
            re.fullmatch(
                r"[A-Za-z0-9][A-Za-z0-9.-]{0,253}",
                host
            )
        )

    if not valid_host:
        return "Invalid host input.", 400

    try:
        # No shell=True.
        # Arguments are passed directly to the operating system.
        result = subprocess.run(
            ["ping", "-c", "1", host],
            capture_output=True,
            text=True,
            timeout=5,
            check=False
        )

        if result.returncode != 0:
            return "Ping failed.", 400

        return f"<pre>{result.stdout}</pre>"

    except subprocess.TimeoutExpired:
        return "Ping timed out.", 408

    except OSError:
        # Do not expose internal system errors.
        return "Ping service unavailable.", 503


@app.route("/search")
def search():
    """Display search input using Flask's template escaping."""

    query = request.args.get("q", "").strip()

    if len(query) > 100:
        return "Search query is too long.", 400

    return render_template_string("""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <title>Secure Search</title>
        </head>
        <body>
            <h2>Search Results</h2>
            <p>You searched for: {{ query }}</p>
        </body>
        </html>
    """, query=query)


if __name__ == "__main__":
    init_db()

    # Debug mode remains disabled.
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False
    )
