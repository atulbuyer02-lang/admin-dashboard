import os
import re
import datetime
from functools import wraps

import jwt
from flask import (
    Flask, render_template, request, redirect, flash, jsonify, session, g
)
from werkzeug.security import generate_password_hash, check_password_hash

from database import get_db_connection

app = Flask(__name__)
app.secret_key = os.environ.get(
    "SECRET_KEY", "dev-secret-key-change-later-use-a-long-random-value"
)


# ---------- access control ----------



def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            return redirect("/login")
        return view(*args, **kwargs)
    return wrapped


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            return redirect("/login")

        if session.get("role") != "admin":
            flash("That page is for admins only.", "error")
            return redirect("/account")

        return view(*args, **kwargs)
    return wrapped

def token_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        header = request.headers.get("Authorization", "")

        if not header.startswith("Bearer "):
            return jsonify({"error": "Missing or invalid Authorization header"}), 401

        token = header[len("Bearer "):]

        try:
            payload = jwt.decode(token, app.secret_key, algorithms=["HS256"])
            g.user_id = int(payload["sub"])
            g.role = payload.get("role")
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token has expired"}), 401
        except (jwt.InvalidTokenError, KeyError, ValueError):
            return jsonify({"error": "Invalid token"}), 401

        return view(*args, **kwargs)
    return wrapped

def admin_token_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        header = request.headers.get("Authorization", "")

        if not header.startswith("Bearer "):
            return jsonify({"error": "Missing or invalid Authorization header"}), 401

        token = header[len("Bearer "):]

        try:
            payload = jwt.decode(token, app.secret_key, algorithms=["HS256"])
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token has expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token"}), 401

        if payload.get("role") != "admin":
            return jsonify({"error": "Admin access required"}), 403

        return view(*args, **kwargs)
    return wrapped


# ---------- register / login / logout ----------

def process_registration(role, heading, action, success_redirect):
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        errors = []

        if not name:
            errors.append("Name is required.")

        if not email:
            errors.append("Email is required.")
        elif not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
            errors.append("Please enter a valid email address.")

        if len(password) < 8:
            errors.append("Password must be at least 8 characters.")
        elif password != confirm_password:
            errors.append("Passwords do not match.")

        connection = get_db_connection()

        if not errors:
            existing = connection.execute(
                "SELECT id FROM users WHERE LOWER(email) = ?",
                (email,)
            ).fetchone()

            if existing:
                errors.append("An account with this email already exists.")

        if errors:
            connection.close()

            for error in errors:
                flash(error, "error")

            return render_template(
                "register.html",
                heading=heading,
                action=action,
                form_data={"name": name, "email": email},
            )

        connection.execute(
            """
            INSERT INTO users (name, email, status, password_hash, role)
            VALUES (?, ?, 'Active', ?, ?)
            """,
            (name, email, generate_password_hash(password), role),
        )
        connection.commit()
        connection.close()

        flash("Account created successfully!", "success")
        return redirect(success_redirect)

    return render_template(
        "register.html", heading=heading, action=action, form_data={}
    )


@app.route("/register", methods=["GET", "POST"])
def register():
    return process_registration(
        role="user",
        heading="Create your account",
        action="/register",
        success_redirect="/login",
    )


@app.route("/admin/register", methods=["GET", "POST"])
@admin_required
def admin_register():
    return process_registration(
        role="admin",
        heading="Create an admin account",
        action="/admin/register",
        success_redirect="/users",
    )


def find_user_by_login(email, password):
    connection = get_db_connection()
    user = connection.execute(
        "SELECT * FROM users WHERE LOWER(email) = ?",
        (email.strip().lower(),)
    ).fetchone()
    connection.close()

    if user is None or user["password_hash"] is None:
        return None

    if not check_password_hash(user["password_hash"], password):
        return None

    return user


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "")
        password = request.form.get("password", "")

        user = find_user_by_login(email, password)

        if user is None:
            flash("Invalid email or password.", "error")
            return render_template("login.html", form_data={"email": email})

        session.clear()
        session["user_id"] = user["id"]
        session["name"] = user["name"]
        session["role"] = user["role"]

        if user["role"] == "admin":
            return redirect("/")

        return redirect("/account")

    return render_template("login.html", form_data={})


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect("/login")


@app.route("/account")
@login_required
def account():
    connection = get_db_connection()
    user = connection.execute(
        "SELECT id, name, email, status, role FROM users WHERE id = ?",
        (session["user_id"],)
    ).fetchone()
    connection.close()

    if user is None:
        session.clear()
        return redirect("/login")

    return render_template("account.html", user=user)


@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({"error": "Request body must be a JSON object"}), 400

    user = find_user_by_login(
        str(data.get("email", "")), str(data.get("password", ""))
    )

    if user is None:
        return jsonify({"error": "Invalid email or password"}), 401

    expires_at = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)

    token = jwt.encode(
        {"sub": str(user["id"]), "role": user["role"], "exp": expires_at},
        app.secret_key,
        algorithm="HS256",
    )

    return jsonify({"token": token, "token_type": "Bearer", "expires_in": 3600})


@app.route("/api/register", methods=["POST"])
def api_register():
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({"error": "Request body must be a JSON object"}), 400

    name = str(data.get("name", "")).strip()
    email = str(data.get("email", "")).strip().lower()
    password = str(data.get("password", ""))

    errors = []

    if not name:
        errors.append("Name is required.")

    if not email:
        errors.append("Email is required.")
    elif not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        errors.append("Please enter a valid email address.")

    if len(password) < 8:
        errors.append("Password must be at least 8 characters.")

    connection = get_db_connection()

    if not errors:
        existing = connection.execute(
            "SELECT id FROM users WHERE LOWER(email) = ?",
            (email,)
        ).fetchone()

        if existing:
            connection.close()
            return jsonify({"error": "An account with this email already exists."}), 409

    if errors:
        connection.close()
        return jsonify({"errors": errors}), 400

    cursor = connection.execute(
        """
        INSERT INTO users (name, email, status, password_hash, role)
        VALUES (?, ?, 'Active', ?, 'user')
        """,
        (name, email, generate_password_hash(password))
    )
    connection.commit()
    new_id = cursor.lastrowid
    connection.close()

    return jsonify({
        "id": new_id,
        "name": name,
        "email": email,
        "role": "user"
    }), 201


@app.route("/api/me")
@token_required
def api_me():
    connection = get_db_connection()
    row = connection.execute(
        "SELECT id, name, email, status, role FROM users WHERE id = ?",
        (g.user_id,)
    ).fetchone()
    connection.close()

    if row is None:
        return jsonify({"error": "User no longer exists"}), 401

    return jsonify(dict(row))


@app.route("/api/me/password", methods=["PUT"])
@token_required
def api_change_password():
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({"error": "Request body must be a JSON object"}), 400

    current_password = str(data.get("current_password", ""))
    new_password = str(data.get("new_password", ""))

    if len(new_password) < 8:
        return jsonify({"error": "New password must be at least 8 characters."}), 400

    connection = get_db_connection()
    row = connection.execute(
        "SELECT password_hash FROM users WHERE id = ?",
        (g.user_id,)
    ).fetchone()

    if row is None:
        connection.close()
        return jsonify({"error": "User no longer exists"}), 401

    if row["password_hash"] is None or not check_password_hash(
        row["password_hash"], current_password
    ):
        connection.close()
        return jsonify({"error": "Current password is incorrect."}), 400

    connection.execute(
        "UPDATE users SET password_hash = ? WHERE id = ?",
        (generate_password_hash(new_password), g.user_id)
    )
    connection.commit()
    connection.close()

    return jsonify({"message": "Password changed successfully"})

# ---------- admin dashboard ----------

@app.route("/")
@admin_required
def home():
    connection = get_db_connection()

    total_users = connection.execute(
        "SELECT COUNT(*) FROM users"
    ).fetchone()[0]

    active_users = connection.execute(
        "SELECT COUNT(*) FROM users WHERE LOWER(status) = ?",
        ("active",)
    ).fetchone()[0]

    inactive_users = connection.execute(
        "SELECT COUNT(*) FROM users WHERE LOWER(status) = ?",
        ("inactive",)
    ).fetchone()[0]

    recent_users = connection.execute(
        """
        SELECT * FROM users
        ORDER BY id DESC
        LIMIT 5
        """
    ).fetchall()

    connection.close()

    return render_template(
        "dashboard.html",
        total_users=total_users,
        active_users=active_users,
        inactive_users=inactive_users,
        recent_users=recent_users
    )




@app.route("/users")
@admin_required
def users():
    search = request.args.get("search", "").strip()

    # Pagination settings
    page = request.args.get("page", 1, type=int)
    page = max(page, 1)
    per_page = 5
    offset = (page - 1) * per_page

    connection = get_db_connection()

    # Count matching users
    if search:
        total_users = connection.execute(
            """
            SELECT COUNT(*) FROM users
            WHERE name LIKE ? OR email LIKE ?
            """,
            (f"%{search}%", f"%{search}%")
        ).fetchone()[0]
    else:
        total_users = connection.execute(
            "SELECT COUNT(*) FROM users"
        ).fetchone()[0]

    # Calculate total pages
    total_pages = max(1, (total_users + per_page - 1) // per_page)

    # Keep requested page within valid limits
    page = min(page, total_pages)
    offset = (page - 1) * per_page

    # Fetch users for the current page
    if search:
        users = connection.execute(
            """
            SELECT * FROM users
            WHERE name LIKE ? OR email LIKE ?
            ORDER BY id DESC
            LIMIT ? OFFSET ?
            """,
            (f"%{search}%", f"%{search}%", per_page, offset)
        ).fetchall()
    else:
        users = connection.execute(
            """
            SELECT * FROM users
            ORDER BY id DESC
            LIMIT ? OFFSET ?
            """,
            (per_page, offset)
        ).fetchall()

    connection.close()

    return render_template(
        "users.html",
        users=users,
        search=search,
        page=page,
        total_pages=total_pages,
        total_users=total_users
    )





@app.route("/users/create", methods=["GET", "POST"])
@admin_required
def create_user():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip()
        status = request.form.get("status", "").strip()

        errors = []

        # Validate name
        if not name:
            errors.append("Name is required.")

        # Validate email
        if not email:
            errors.append("Email is required.")
        elif not re.fullmatch(
            r"[^@\s]+@[^@\s]+\.[^@\s]+", email
        ):
            errors.append("Please enter a valid email address.")

        # Validate status
        if status not in ("Active", "Inactive"):
            errors.append("Please select a valid status.")

        # Show errors and keep entered values
        if errors:
            for error in errors:
                flash(error, "error")

            return render_template(
                "create_user.html",
                form_data={
                    "name": name,
                    "email": email,
                    "status": status,
                },
            )

        connection = get_db_connection()
        connection.execute(
            """
            INSERT INTO users (name, email, status)
            VALUES (?, ?, ?)
            """,
            (name, email, status),
        )
        connection.commit()
        connection.close()

        flash("User created successfully!", "success")
        return redirect("/users")

    return render_template("create_user.html", form_data={})


@app.route("/users/edit/<int:user_id>", methods=["GET", "POST"])
@admin_required
def edit_user(user_id):

    connection = get_db_connection()

    user = connection.execute(
        "SELECT * FROM users WHERE id = ?",
        (user_id,)
    ).fetchone()

    if user is None:
        connection.close()
        return "User not found", 404

    if request.method == "POST":

        name = request.form["name"]
        email = request.form["email"]
        status = request.form["status"]

        connection.execute(
            """
            UPDATE users
            SET name = ?, email = ?, status = ?
            WHERE id = ?
            """,
            (name, email, status, user_id)
        )

        connection.commit()
        connection.close()
        flash("User updated successfully!", "success")
        return redirect("/users")

    connection.close()

    return render_template("edit_user.html", user=user)

@app.route("/users/delete/<int:user_id>", methods=["POST"])
@admin_required
def delete_user(user_id):

    connection = get_db_connection()

    connection.execute(
        "DELETE FROM users WHERE id = ?",
        (user_id,)
    )

    connection.commit()
    connection.close()
    flash("User deleted successfully!", "success")
    return redirect("/users")


# ---------- API (admin token required) ----------

@app.route("/api/users")
@admin_token_required
def api_users():
    connection = get_db_connection()

    rows = connection.execute(
        "SELECT id, name, email, status, role FROM users ORDER BY id DESC"
    ).fetchall()

    connection.close()

    return jsonify([dict(row) for row in rows])


@app.route("/api/users/<int:user_id>")
@admin_token_required
def api_user(user_id):
    connection = get_db_connection()

    row = connection.execute(
        "SELECT id, name, email, status, role FROM users WHERE id = ?",
        (user_id,)
    ).fetchone()

    connection.close()

    if row is None:
        return jsonify({"error": "User not found"}), 404

    return jsonify(dict(row))

@app.route("/api/users", methods=["POST"])
@admin_token_required
def api_create_user():
    data = request.get_json(silent=True)

    if not isinstance(data,     dict):
        return jsonify({"error": "Request body must be a JSON object"}), 400

    name = str(data.get("name", "")).strip()
    email = str(data.get("email", "")).strip()
    status = str(data.get("status", "")).strip()

    errors = []

    if not name:
        errors.append("Name is required.")

    if not email:
        errors.append("Email is required.")
    elif not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        errors.append("Please enter a valid email address.")

    if status not in ("Active", "Inactive"):
        errors.append("Status must be Active or Inactive.")

    if errors:
        return jsonify({"errors": errors}), 400

    connection = get_db_connection()
    cursor = connection.execute(
        "INSERT INTO users (name, email, status) VALUES (?, ?, ?)",
        (name, email, status)
    )
    connection.commit()
    new_id = cursor.lastrowid
    connection.close()

    return jsonify({
        "id": new_id,
        "name": name,
        "email": email,
        "status": status
    }), 201

@app.route("/api/users/<int:user_id>", methods=["PUT"])
@admin_token_required
def api_update_user(user_id):
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({"error": "Request body must be a JSON object"}), 400

    name = str(data.get("name", "")).strip()
    email = str(data.get("email", "")).strip()
    status = str(data.get("status", "")).strip()

    errors = []

    if not name:
        errors.append("Name is required.")

    if not email:
        errors.append("Email is required.")
    elif not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        errors.append("Please enter a valid email address.")

    if status not in ("Active", "Inactive"):
        errors.append("Status must be Active or Inactive.")

    if errors:
        return jsonify({"errors": errors}), 400

    connection = get_db_connection()

    cursor = connection.execute(
        "UPDATE users SET name = ?, email = ?, status = ? WHERE id = ?",
        (name, email, status, user_id)
    )
    connection.commit()
    updated = cursor.rowcount
    connection.close()

    if updated == 0:
        return jsonify({"error": "User not found"}), 404

    return jsonify({
        "id": user_id,
        "name": name,
        "email": email,
        "status": status
    })


@app.route("/api/users/<int:user_id>", methods=["DELETE"])
@admin_token_required
def api_delete_user(user_id):
    connection = get_db_connection()

    cursor = connection.execute(
        "DELETE FROM users WHERE id = ?",
        (user_id,)
    )
    connection.commit()
    deleted = cursor.rowcount
    connection.close()

    if deleted == 0:
        return jsonify({"error": "User not found"}), 404

    return jsonify({"message": "User deleted successfully"})



if __name__ == "__main__":
    app.run(debug=True)