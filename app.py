import os
import time
import codecs
from flask import Flask, request, session, render_template_string, redirect, url_for, send_from_directory
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)
app.secret_key = "secret_key_for_ctf_2026"

# Cấu hình Rate Limiting
limiter = Limiter(get_remote_address, app=app, default_limits=["200 per day", "50 per hour"])

# Cơ sở dữ liệu người dùng
USERS_DB = {
    "support_staff": {"pass": "password_bi_an_123", "role": "support"},
    "admin": {"pass": "admin_super_secret_pass_2026", "role": "quanly"}
}
AUTH_ATTEMPTS = {}

# Chặn các tool scan tự động
@app.before_request
def block_scanners():
    ua = request.headers.get('User-Agent', '').lower()
    if any(s in ua for s in ['dirsearch', 'gobuster', 'sqlmap', 'nmap']):
        return "403 Forbidden - Scanner detected", 403

@app.route("/", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def login():
    if request.method == "POST":
        u, p = request.form.get("user"), request.form.get("pass")
        if u in USERS_DB and USERS_DB[u]["pass"] == p:
            session.update({"user": u, "role": USERS_DB[u]["role"]})
            return redirect(url_for("panel"))
        return "Invalid credentials"
    return "<h2>Login</h2><form method='POST'>User: <input name='user'><br>Pass: <input type='password' name='pass'><br><input type='submit'></form><br><a href='/register'>Register</a>"

@app.route("/register", methods=["POST"])
@limiter.limit("3 per minute")
def register():
    u, p, r = request.form.get("user"), request.form.get("pass"), request.form.get("role", "guest")
    # Honey Pot: Nếu người dùng cố ý leo quyền ngay tại bước đăng ký
    if r != "guest":
        with open("logs/security.log", "a") as f:
            f.write(f"ALERT: Unauthorized role attempt by {u} as {r}\n")
        return "Unauthorized privilege escalation attempt logged!", 403
    USERS_DB[u] = {"pass": p, "role": r}
    return "Registration successful!"

@app.route("/panel")
def panel():
    return render_template_string('''
        <h3>User: {{ session.get("user") }} | Role: {{ session.get("role") }}</h3>
        {% if session.get("role") == "quanly" %}
            <p>Welcome Manager! Access Flag 2: <a href="/internal-assets/cerdentials.txt.bak">cerdentials.txt.bak</a></p>
        {% elif session.get("role") == "support" %}
            <p>System Logs: <a href="/view-log?file=app.log">View app.log</a></p>
        {% endif %}
        {% if session.get("user") == "admin" %}
            <p>Admin Portal: <a href="/admin">Go to Admin</a></p>
        {% endif %}
    ''')

@app.route("/admin")
def admin_panel():
    if session.get("user") == "admin":
        return "Congrats! This is Flag 3: FLAG{admin_privileged_access_granted_2026}"
    return "Access Denied", 403

@app.route("/internal-assets/<path:filename>")
def secure_assets(filename):
    if session.get("role") != "quanly":
        return "403 Forbidden", 403
    return send_from_directory("internal_assets", filename)

@app.route("/view-log")
def view_log():
    # Lỗ hổng Path Traversal
    if session.get("user") != "support_staff":
        return "403 Forbidden", 403
    try:
        file_path = os.path.join("logs", request.args.get("file"))
        return open(file_path, "r").read()
    except:
        return "File not found", 404

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)