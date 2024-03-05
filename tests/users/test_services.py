import logging

import pytest

from apps.users.services import (ActivationService, LoginService,
                                 RegistrationService)
from tests.users.factories import UserFactory

logger = logging.getLogger("django")
pytestmark = pytest.mark.django_db


class TestRegistrationService:
    def test_register_user(self):
        data = {
            "username": "testuser",
            "email": "testuser@gmail.com",
            "password": "testpass$",
        }
        data, user = RegistrationService.register_user(data)
        assert user.username == "testuser"
        assert user.email == "testuser@gmail.com"
        assert data["access_token"] is not None
        assert data["refresh_token"] is not None


class TestLoginService:
    def test_login_user(self):
        data = {
            "username": "testuser",
            "password": "testpass$",
        }
        UserFactory.create(username="testuser", password="testpass$")
        data = LoginService.login_user(data)
        assert data["access_token"] is not None
        assert data["refresh_token"] is not None
        assert data["username"] == "testuser"


class TestActivationService:
    def test_activate_user(self):
        user = UserFactory.create(username="testuser", password="testpass$")
        user = ActivationService.activate_user(user)
        assert user.is_active == True
        assert user.is_verified == True
