
from flask import Flask, render_template, request, jsonify, redirect, url_for, session
import openai, os, json, bcrypt
from dotenv import load_dotenv

load_dotenv()
app = Flask(__name__)
app.secret_key = "supersecret"
openai.api_key = os.getenv("OPENAI_API_KEY")
kai_active = True

def load_users():
    with open("users.json") as f:
        return json.load(f)

def save_users(users):
    with open("users.json", "w") as f:
        json.dump(users, f)

def hash_password(password):
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

def check_password(password, hashed):
    return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))

def load_knowledge():
    if os.path.exists("knowledge.json"):
        with open("knowledge.json") as f:
            return json.load(f)
    return {}

def save_knowledge(data):
    with open("knowledge.json", "w") as f:
        json.dump(data, f)

@app.route("/")
def home():
    if "username" not in session:
        return redirect(url_for("login"))
    return render_template("index.html", username=session["username"], role=session["role"])

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        users = load_users()
        username = request.form["username"]
        password = request.form["password"]

        if username in users and check_password(password, users[username]["password"]):
            session["username"] = username
            session["role"] = users[username]["role"]
            return redirect(url_for("home"))
        return render_template("login.html", error="❌ Falscher Name oder Passwort.")

    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        role = request.form.get("role", "user")
        users = load_users()

        if username in users:
            return render_template("register.html", error="Benutzer existiert bereits!")

        users[username] = {
            "password": hash_password(password),
            "role": role
        }
        save_users(users)
        return redirect(url_for("login"))

    return render_template("register.html")

@app.route("/admin", methods=["GET", "POST"])
def admin_panel():
    if session.get("role") != "admin":
        return redirect("/")
    users = load_users()
    if request.method == "POST":
        action = request.form["action"]
        username = request.form["username"]
        if action == "delete" and username in users and username != "admin":
            del users[username]
        elif action == "promote":
            users[username]["role"] = "admin"
        elif action == "demote":
            users[username]["role"] = "user"
        save_users(users)
        return redirect(url_for("admin_panel"))
    return render_template("admin.html", users=users)

@app.route("/toggle", methods=["POST"])
def toggle_kai():
    global kai_active
    if session.get("role") != "admin":
        return jsonify({"error": "Nur Admins dürfen KAI aktivieren/deaktivieren."})
    kai_active = not kai_active
    return jsonify({"active": kai_active})

@app.route("/chat", methods=["POST"])
def chat():
    global kai_active
    if not kai_active:
        return jsonify({"reply": "⚠️ KAI ist deaktiviert."})
    user_message = request.json.get("message")
    knowledge = load_knowledge()
    context = [{"role": "system", "content": "Du bist KAI, eine hilfsbereite und kreative KI."}]
    if knowledge:
        facts = "\n".join([f"{k}: {v}" for k, v in knowledge.items()])
        context.append({"role": "system", "content": f"Gespeichertes Wissen:\n{facts}"})
    context.append({"role": "user", "content": user_message})
    response = openai.ChatCompletion.create(model="gpt-4", messages=context)
    reply = response.choices[0].message["content"].strip()
    if "ich heiße" in user_message.lower():
        name = user_message.lower().split("ich heiße")[-1].strip().split()[0]
        knowledge["Name"] = name
        save_knowledge(knowledge)
    return jsonify({"reply": reply})

if __name__ == "__main__":
    app.run(debug=True)
