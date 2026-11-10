from getpass import getpass

from werkzeug.security import generate_password_hash

from database import get_db_connection


name = input("Admin name: ").strip()
email = input("Admin email: ").strip().lower()
password = getpass("Admin password: ")

if not name or not email or len(password) < 8:
    print("Name and email are required, and the password must be 8+ characters.")
    raise SystemExit(1)

connection = get_db_connection()

try:
    existing = connection.execute(
        "SELECT id FROM users WHERE LOWER(email) = ?", (email,)
    ).fetchone()

    if existing:
        print("A user with this email already exists.")
        raise SystemExit(1)

    connection.execute(
        """
        INSERT INTO users (name, email, status, password_hash, role)
        VALUES (?, ?, 'Active', ?, 'admin')
        """,
        (name, email, generate_password_hash(password)),
    )
    connection.commit()
    print(f"Admin '{email}' created.")
finally:
    connection.close()