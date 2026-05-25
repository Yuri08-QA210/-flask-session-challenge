import os
import base64
import time
from flask import Flask, request, session, render_template_string, redirect, url_for, send_from_directory

app = Flask(__name__)
app.secret_key = "secret_key_for_ctf_2026"

AUTH_ATTEMPTS = {}
USERS_DB = {
    "support_staff": {"pass": "password_bi_an_123", "role": "support"}
}

LOGIN_PAGE = '''
<h2>Login</h2><form method="POST" action="/">
Username: <input type="text" name="user"><br>
Password: <input type="password" name="pass"><br>
<input type="submit" value="Login"></form>
<a href="/register">Register</a>'''

REGISTER_PAGE = '''
<h2>Register</h2><form method="POST" action="/register">
Username: <input type="text" name="user"><br>
Password: <input type="password" name="pass"><br>
<input type="submit" value="Register"></form>'''

PANEL_PAGE = '''
<h3>User: {{ session.get("user") }} | Role: {{ session.get("role") }}</h3>
{% if session.get("role") == "quanly" %}
    <p>Welcome Manager! You have access to: <a href="/internal-assets/credentials.txt.bak">credentials.txt.bak</a></p>
{% elif session.get("user") == "support_staff" %}
    <p>System Logs: <a href="/view-log?file=app.log">View app.log</a></p>
{% else %}
    <p>Manager role required to view assets.</p>
{% endif %}'''

@app.before_request
def block_scanners():
    ua = request.headers.get('User-Agent', '').lower()
    if any(s in ua for s in ['dirsearch', 'gobuster', 'sqlmap', 'nmap']):
        return "403 Forbidden", 403

@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        u, p = request.form.get("user"), request.form.get("pass")
        if u in USERS_DB and USERS_DB[u]["pass"] == p:
            session.update({"user": u, "role": USERS_DB[u]["role"]})
            return redirect(url_for("panel"))
        return "Invalid credentials"
    return render_template_string(LOGIN_PAGE)

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        u, p, r = request.form.get("user"), request.form.get("pass"), request.form.get("role", "guest")
        now = time.time()
        if r != "guest":
            attempts = AUTH_ATTEMPTS.get(u, {"count": 0, "time": now})
            if attempts["count"] >= 5 and (now - attempts["time"] < 300):
                return "Account locked for 5 minutes due to spamming!", 403
            AUTH_ATTEMPTS[u] = {"count": attempts["count"] + 1, "time": now}
            return "Unauthorized privilege escalation attempt logged!", 403
        USERS_DB[u] = {"pass": p, "role": r}
        return "Registration successful!"
    return render_template_string(REGISTER_PAGE)

@app.route("/panel")
def panel():
    return render_template_string(PANEL_PAGE)

@app.route("/internal-assets/<path:filename>")
def secure_assets(filename):
    if session.get("role") != "quanly":
        return "403 Forbidden", 403
    return send_from_directory("internal_assets", filename)

@app.route("/view-log")
def view_log():
    if session.get("user") != "support_staff":
        return "403 Forbidden", 403
    with open(os.path.join("logs", request.args.get("file")), "r") as f:
        return f.read()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)