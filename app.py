
import json
import secrets
import subprocess
import sys
import time
from pathlib import Path
from collections import defaultdict

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash, abort
)
from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)

app = Flask(__name__)

app.secret_key = secrets.token_hex(32)

BASE_DIR = Path(__file__).resolve().parent
CONFIG_FILE = BASE_DIR / "remote_config.json"

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Strict",
    SESSION_COOKIE_SECURE=False
)

# Generate a password on the first run.

def load_config():
    if CONFIG_FILE.exists():
        return json.loads(
            CONFIG_FILE.read_text(encoding="utf-8")
        )

    password = secrets.token_urlsafe(18)

    config = {
        "password_hash": generate_password_hash(password)
    }

    CONFIG_FILE.write_text(
        json.dumps(config, indent=4),
        encoding="utf-8"
    )

    print("\n" + "=" * 45, flush=True)
    print("YOUR ADRAXO REMOTE PASSWORD:", flush=True)
    print(password, flush=True)
    print("=" * 45, flush=True)
    print("Save this password somewhere safe!\n", flush=True)

    return config



config = load_config()

# Basic login attempt protection.
login_attempts = defaultdict(list)


def check_login_attempts(ip):
    now = time.time()
    login_attempts[ip] = [
        t for t in login_attempts[ip]
        if now - t < 300
    ]
    return len(login_attempts[ip]) < 5


def csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return session["csrf_token"]


def verify_csrf():
    supplied = request.form.get("csrf_token", "")
    expected = session.get("csrf_token", "")

    if not expected or not secrets.compare_digest(
        supplied, expected
    ):
        abort(400, "Invalid security token. Refresh the page.")


def login_required():
    return session.get("logged_in") is True


@app.route("/", methods=["GET", "POST"])
def login():
    if login_required():
        return redirect(url_for("dashboard"))

    error = None
    ip = request.remote_addr or "unknown"

    if request.method == "POST":
        verify_csrf()

        if not check_login_attempts(ip):
            error = "Too many attempts. Try again after 5 minutes."
        else:
            password = request.form.get("password", "")

            if check_password_hash(
                config["password_hash"], password
            ):
                login_attempts[ip].clear()
                session.clear()
                session["logged_in"] = True
                session["csrf_token"] = secrets.token_urlsafe(32)
                return redirect(url_for("dashboard"))

            login_attempts[ip].append(time.time())
            error = "Incorrect password."

    return render_template(
        "index.html",
        page="login",
        csrf=csrf_token(),
        error=error
    )


@app.route("/dashboard")
def dashboard():
    if not login_required():
        return redirect(url_for("login"))

    return render_template(
        "index.html",
        page="dashboard",
        csrf=csrf_token()
    )


@app.route("/action", methods=["POST"])
def action():
    if not login_required():
        abort(401)

    verify_csrf()

    if sys.platform != "win32":
        abort(403, "This program requires Windows.")

    command = request.form.get("command")

    try:
        if command == "lock":
            subprocess.Popen([
                "rundll32.exe",
                "user32.dll,LockWorkStation"
            ])
            flash("Lock command sent!", "success")

        elif command == "shutdown":
            subprocess.Popen([
                "shutdown.exe", "/s", "/t", "30"
            ])
            flash("Shutdown scheduled in 30 seconds.", "success")

        elif command == "restart":
            subprocess.Popen([
                "shutdown.exe", "/r", "/t", "30"
            ])
            flash("Restart scheduled in 30 seconds.", "success")

        elif command == "cancel":
            subprocess.Popen([
                "shutdown.exe", "/a"
            ])
            flash("Pending shutdown/restart cancelled.", "success")

        else:
            abort(400, "Invalid command.")

    except OSError:
        flash("Could not execute the command.", "error")

    return redirect(url_for("dashboard"))


@app.route("/logout", methods=["POST"])
def logout():
    if not login_required():
        return redirect(url_for("login"))

    verify_csrf()
    session.clear()

    return redirect(url_for("login"))


if __name__ == "__main__":
    print("Starting ADRAXO REMOTE...")
    print("Local address: http://127.0.0.1:8765")

    app.run(
        host="127.0.0.1",
        port=8765,
        debug=False
    )
