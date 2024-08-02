from builtins import str
import pytest
from httpx import AsyncClient
from app.main import app
from app.models.user_model import User, UserRole
from app.utils.nickname_gen import generate_nickname
from app.utils.security import hash_password
from app.services.jwt_service import decode_token
from urllib.parse import urlencode


# User Creation Tests

@pytest.mark.asyncio
async def test_create_user_access_denied(async_client, user_token, email_service):
    """Test creating a user with a regular user token should be denied."""
    headers = {"Authorization": f"Bearer {user_token}"}
    user_data = {
        "nickname": generate_nickname(),
        "email": "test@example.com",
        "password": "sS#fdasrongPassword123!",
    }
    response = await async_client.post("/users/", json=user_data, headers=headers)
    assert response.status_code == 403

@pytest.mark.asyncio
async def test_create_user_invalid_password(async_client):
    """Test creating a user with an invalid password should return a validation error."""
    user_data = {
        "nickname": generate_nickname(),
        "email": "test_invalid_pass@example.com",
        "password": "short",
    }
    response = await async_client.post("/users/", json=user_data)
    assert response.status_code == 422

@pytest.mark.asyncio
async def test_create_user_existing_nickname(async_client, verified_user):
    """Test creating a user with an existing nickname should return an error."""
    user_data = {
        "nickname": verified_user.nickname,
        "email": "newemail@example.com",
        "password": "AnotherStrongPassword123!",
    }
    response = await async_client.post("/users/", json=user_data)
    assert response.status_code == 400
    assert "Nickname already exists" in response.json().get("detail", "")

@pytest.mark.asyncio
async def test_create_user_duplicate_email(async_client, verified_user):
    """Test creating a user with a duplicate email should return an error."""
    user_data = {
        "email": verified_user.email,
        "password": "AnotherPassword123!",
        "role": UserRole.ADMIN.name
    }
    response = await async_client.post("/register/", json=user_data)
    assert response.status_code == 400
    assert "Email already exists" in response.json().get("detail", "")

@pytest.mark.asyncio
async def test_create_user_invalid_email(async_client):
    """Test creating a user with an invalid email should return a validation error."""
    user_data = {
        "email": "notanemail",
        "password": "ValidPassword123!",
    }
    response = await async_client.post("/register/", json=user_data)
    assert response.status_code == 422


# User Retrieval Tests

@pytest.mark.asyncio
async def test_retrieve_user_access_denied(async_client, verified_user, user_token):
    """Test retrieving a user with a regular user token should be denied."""
    headers = {"Authorization": f"Bearer {user_token}"}
    response = await async_client.get(f"/users/{verified_user.id}", headers=headers)
    assert response.status_code == 403

@pytest.mark.asyncio
async def test_retrieve_user_access_allowed(async_client, admin_user, admin_token):
    """Test retrieving a user with an admin token should be allowed."""
    headers = {"Authorization": f"Bearer {admin_token}"}
    response = await async_client.get(f"/users/{admin_user.id}", headers=headers)
    assert response.status_code == 200
    assert response.json()["id"] == str(admin_user.id)


# User Update Tests

@pytest.mark.asyncio
async def test_update_user_email_access_denied(async_client, verified_user, user_token):
    """Test updating a user's email with a regular user token should be denied."""
    updated_data = {"email": f"updated_{verified_user.id}@example.com"}
    headers = {"Authorization": f"Bearer {user_token}"}
    response = await async_client.put(f"/users/{verified_user.id}", json=updated_data, headers=headers)
    assert response.status_code == 403

@pytest.mark.asyncio
async def test_update_user_email_access_allowed(async_client, admin_user, admin_token):
    """Test updating a user's email with an admin token should be allowed."""
    updated_data = {"email": f"updated_{admin_user.id}@example.com"}
    headers = {"Authorization": f"Bearer {admin_token}"}
    response = await async_client.put(f"/users/{admin_user.id}", json=updated_data, headers=headers)
    assert response.status_code == 200
    assert response.json()["email"] == updated_data["email"]

@pytest.mark.asyncio
async def test_update_user_unauthorized(async_client, verified_user):
    """Test updating a user without a token should be unauthorized."""
    updated_data = {"email": f"unauthorized_{verified_user.id}@example.com"}
    response = await async_client.put(f"/users/{verified_user.id}", json=updated_data)
    assert response.status_code == 401

@pytest.mark.asyncio
async def test_update_user_github(async_client, admin_user, admin_token):
    """Test updating a user's GitHub profile URL with an admin token should be allowed."""
    updated_data = {"github_profile_url": "http://www.github.com/kaw393939"}
    headers = {"Authorization": f"Bearer {admin_token}"}
    response = await async_client.put(f"/users/{admin_user.id}", json=updated_data, headers=headers)
    assert response.status_code == 200
    assert response.json()["github_profile_url"] == updated_data["github_profile_url"]

@pytest.mark.asyncio
async def test_update_user_linkedin(async_client, admin_user, admin_token):
    """Test updating a user's LinkedIn profile URL with an admin token should be allowed."""
    updated_data = {"linkedin_profile_url": "http://www.linkedin.com/kaw393939"}
    headers = {"Authorization": f"Bearer {admin_token}"}
    response = await async_client.put(f"/users/{admin_user.id}", json=updated_data, headers=headers)
    assert response.status_code == 200
    assert response.json()["linkedin_profile_url"] == updated_data["linkedin_profile_url"]


# User Deletion Tests

@pytest.mark.asyncio
async def test_delete_user(async_client, admin_user, admin_token):
    """Test deleting a user with an admin token should be allowed."""
    headers = {"Authorization": f"Bearer {admin_token}"}
    delete_response = await async_client.delete(f"/users/{admin_user.id}", headers=headers)
    assert delete_response.status_code == 204
    fetch_response = await async_client.get(f"/users/{admin_user.id}", headers=headers)
    assert fetch_response.status_code == 404

@pytest.mark.asyncio
async def test_delete_user_does_not_exist(async_client, admin_token):
    """Test deleting a non-existent user should return a not found error."""
    non_existent_user_id = "00000000-0000-0000-0000-000000000000"
    headers = {"Authorization": f"Bearer {admin_token}"}
    delete_response = await async_client.delete(f"/users/{non_existent_user_id}", headers=headers)
    assert delete_response.status_code == 404


# User Authentication Tests

@pytest.mark.asyncio
async def test_login_success(async_client, verified_user):
    """Test logging in with valid credentials should succeed."""
    form_data = {
        "username": verified_user.email,
        "password": "MySuperPassword$1234"
    }
    response = await async_client.post("/login/", data=urlencode(form_data), headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    decoded_token = decode_token(data["access_token"])
    assert decoded_token is not None
    assert decoded_token["role"] == "AUTHENTICATED"

@pytest.mark.asyncio
async def test_login_user_not_found(async_client):
    """Test logging in with a non-existent user should return an error."""
    form_data = {
        "username": "nonexistentuser@here.edu",
        "password": "DoesNotMatter123!"
    }
    response = await async_client.post("/login/", data=urlencode(form_data), headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert response.status_code == 401
    assert "Incorrect email or password." in response.json().get("detail", "")

@pytest.mark.asyncio
async def test_login_incorrect_password(async_client, verified_user):
    """Test logging in with an incorrect password should return an error."""
    form_data = {
        "username": verified_user.email,
        "password": "IncorrectPassword123!"
    }
    response = await async_client.post("/login/", data=urlencode(form_data), headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert response.status_code == 401
    assert "Incorrect email or password." in response.json().get("detail", "")

@pytest.mark.asyncio
async def test_login_unverified_user(async_client, unverified_user):
    """Test logging in with an unverified user should return an error."""
    form_data = {
        "username": unverified_user.email,
        "password": "MySuperPassword$1234"
    }
    response = await async_client.post("/login/", data=urlencode(form_data), headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert response.status_code == 401

@pytest.mark.asyncio
async def test_login_locked_user(async_client, locked_user):
    """Test logging in with a locked user should return an error."""
    form_data = {
        "username": locked_user.email,
        "password": "MySuperPassword$1234"
    }
    response = await async_client.post("/login/", data=urlencode(form_data), headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert response.status_code == 401


# User Listing Tests

@pytest.mark.asyncio
async def test_list_users(async_client, admin_token):
    """Test listing users with an admin token should succeed."""
    headers = {"Authorization": f"Bearer {admin_token}"}
    response = await async_client.get("/users/", headers=headers)
    assert response.status_code == 200
    assert isinstance(response.json(), list)
    assert len(response.json()) > 0

@pytest.mark.asyncio
async def test_list_users_access_denied(async_client, user_token):
    """Test listing users with a regular user token should be denied."""
    headers = {"Authorization": f"Bearer {user_token}"}
    response = await async_client.get("/users/", headers=headers)
    assert response.status_code == 403
