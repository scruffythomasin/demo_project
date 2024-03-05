import logging

import pytest
from django.core import mail
from model_bakery import baker

from apps.users.models import User

logger = logging.getLogger("django")

pytestmark = pytest.mark.django_db


class TestRegisterEndpoint:
    endpoint = "/api/v1/users/register/"

    def test_register_password_special_symbol_error(self, api_client):
        expected_json = {
            "username": "testuser",
            "email": "testuser@gmail.com",
            "password": "testpassword",
            "confirm_password": "testpassword",
        }
        error = {"password": ["Password must have special character"]}

        with pytest.raises(AssertionError) as exc:
            response = api_client.post(self.endpoint, expected_json)
            assert response.status_code == 200
        assert response.json() == error

    def test_register_password_length_error(self, api_client):
        expected_json = {
            "username": "testuser",
            "email": "testuser@gmail.com",
            "password": "testpa#",
            "confirm_password": "testpa#",
        }
        error = {"password": ["Password must be at least 8 characters long"]}
        with pytest.raises(AssertionError) as exc:
            response = api_client.post(self.endpoint, expected_json)
            assert response.status_code == 200
        assert response.json() == error

    def test_register_username_length_error(self, api_client):
        expected_json = {
            "username": "test",
            "email": "testuser@gmail.com",
            "password": "testpass#",
            "confirm_password": "testpass#",
        }
        error = {"username": ["Username must be at least 5 characters long"]}
        with pytest.raises(AssertionError) as exc:
            response = api_client.post(self.endpoint, expected_json)
            assert response.status_code == 200
        assert response.json() == error

    def test_register_username_alphanumeric_error(self, api_client):
        expected_json = {
            "username": "testuser@",
            "email": "test@gmail.com",
            "password": "testpass#",
            "confirm_password": "testpass#",
        }
        error = {"username": ["Username must be alphanumeric"]}
        with pytest.raises(AssertionError) as exc:
            response = api_client.post(self.endpoint, expected_json)
            assert response.status_code == 200
        assert response.json() == error

    def test_register_username_exists_error(self, api_client):
        user = baker.make(User)
        expected_json = {
            "username": user.username,
            "email": "testuser@gmail.com",
            "password": "testpass$",
            "confirm_password": "testpass$",
        }
        error = {"username": ["Username already exists"]}
        with pytest.raises(AssertionError) as exc:
            response = api_client.post(self.endpoint, expected_json)
            assert response.status_code == 200
        assert response.json() == error

    def test_register_email_exists_error(self, api_client):
        user = baker.make(User)
        expected_json = {
            "username": "testuser",
            "email": user.email,
            "password": "testpass$",
            "confirm_password": "testpass$",
        }
        error = {"email": ["Email already exists"]}
        with pytest.raises(AssertionError) as exc:
            response = api_client.post(self.endpoint, expected_json)
            assert response.status_code == 200
        assert response.json() == error

    def test_register_passwords_not_match_error(self, api_client):
        expected_json = {
            "username": "testuser",
            "email": "test@gmail.com",
            "password": "testpass1$",
            "confirm_password": "testpass$",
        }
        error = {"password": ["Passwords do not match"]}
        with pytest.raises(AssertionError) as exc:
            response = api_client.post(self.endpoint, expected_json)
            assert response.status_code == 200
        assert response.json() == error

    def test_register_success(self, api_client):
        expected_json = {
            "username": "testuser",
            "email": "testuser@gmail.com",
            "password": "testpass$",
            "confirm_password": "testpass$",
        }
        response = api_client.post(self.endpoint, expected_json)
        expected_json.pop("password")
        expected_json.pop("confirm_password")
        assert response.status_code == 201
        assert response.json()["access_token"] != None
        assert response.json()["refresh_token"] != None

    def test_register_email_verification(self, api_client):
        expected_json = {
            "username": "testuser",
            "email": "testuser@gmail.com",
            "password": "testpass$",
            "confirm_password": "testpass$",
        }
        response = api_client.post(self.endpoint, expected_json)
        assert response.status_code == 201
        user = User.objects.get(username=expected_json["username"])
        assert user.is_verified == False
        assert len(mail.outbox) == 1
        assert mail.outbox[0].to[0] == expected_json["email"]
        response = api_client.get(mail.outbox[0].body)
        assert response.status_code == 200
        user = User.objects.get(username=expected_json["username"])
        assert user.is_verified == True
        message = {"message:": "Account verified successfully"}
        assert response.json() == message


class TestLoginEndpoint:
    endpoint = "/api/v1/users/login/"

    def test_login_success(self, api_client):
        user = User.objects.create_user(username="testuser", password="testpass$")
        expected_json = {"username": user.username, "password": "testpass$"}
        response = api_client.post(self.endpoint, expected_json)
        assert response.status_code == 200
        assert response.json()["access_token"] != None
        assert response.json()["refresh_token"] != None
