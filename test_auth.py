import pytest
from werkzeug.security import generate_password_hash

import database
from app import app


@pytest.fixture
def client(tmp_path, monkeypatch):
    # Point the app at a throwaway database so tests never touch database.db
    monkeypatch.setattr(database, "DATABASE", str(tmp_path / "test.db"))
    database.create_users_table()
    database.add_auth_columns()

    app.config["TESTING"] = True
    return app.test_client()


def make_user(email, password, role="user", name="Test"):
    connection = database.get_db_connection()
    connection.execute(
        """
        INSERT INTO users (name, email, status, password_hash, role)
        VALUES (?, ?, 'Active', ?, ?)
        """,
        (name, email, generate_password_hash(password), role),
    )
    connection.commit()
    connection.close()


def get_token(client, email, password):
    response = client.post("/api/login", json={"email": email, "password": password})
    return response.get_json()["token"]


def auth_header(token):
    return {"Authorization": f"Bearer {token}"}


def test_register_creates_user(client):
    response = client.post(
        "/api/register",
        json={"name": "Sam", "email": "sam@test.com", "password": "password1"},
    )

    assert response.status_code == 201
    assert response.get_json()["role"] == "user"


def test_register_duplicate_email_is_rejected(client):
    make_user("sam@test.com", "password1")

    response = client.post(
        "/api/register",
        json={"name": "Sam", "email": "SAM@test.com", "password": "password1"},
    )

    assert response.status_code == 409


def test_login_with_wrong_password_returns_401(client):
    make_user("sam@test.com", "password1")

    response = client.post(
        "/api/login", json={"email": "sam@test.com", "password": "wrong"}
    )

    assert response.status_code == 401


def test_api_users_without_token_returns_401(client):
    response = client.get("/api/users")

    assert response.status_code == 401


def test_normal_user_token_gets_403_on_admin_route(client):
    make_user("sam@test.com", "password1", role="user")
    token = get_token(client, "sam@test.com", "password1")

    response = client.get("/api/users", headers=auth_header(token))

    assert response.status_code == 403


def test_admin_token_can_list_users(client):
    make_user("boss@test.com", "password1", role="admin")
    token = get_token(client, "boss@test.com", "password1")

    response = client.get("/api/users", headers=auth_header(token))

    assert response.status_code == 200
    assert len(response.get_json()) == 1


def test_api_never_returns_password_hash(client):
    make_user("boss@test.com", "password1", role="admin")
    token = get_token(client, "boss@test.com", "password1")

    response = client.get("/api/users", headers=auth_header(token))

    assert "password_hash" not in response.get_json()[0]


def test_me_returns_own_profile(client):
    make_user("sam@test.com", "password1", name="Sam")
    token = get_token(client, "sam@test.com", "password1")

    response = client.get("/api/me", headers=auth_header(token))

    assert response.status_code == 200
    assert response.get_json()["email"] == "sam@test.com"


def test_dashboard_redirects_to_login_when_logged_out(client):
    response = client.get("/")

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/login")