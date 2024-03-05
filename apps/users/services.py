import logging

from django.core.mail import send_mail
from django.urls import reverse
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from rest_framework_simplejwt.serializers import RefreshToken

from .repositories import UserRepository
from .tokens import activation_token

logger = logging.getLogger("django")


class RegistrationService:
    @staticmethod
    def register_user(data):
        user = UserRepository.create_user(data)
        if user:
            token = RefreshToken.for_user(user)
            data["access_token"] = str(token.access_token)
            data["refresh_token"] = str(token)
            return data, user
        else:
            return None


class LoginService:
    @staticmethod
    def login_user(data):
        username = data.get("username")
        password = data.pop("password")
        user = UserRepository.get_user_by_username(username)
        if user and user.check_password(password):
            token = RefreshToken.for_user(user)
            data["access_token"] = str(token.access_token)
            data["refresh_token"] = str(token)
            return data
        else:
            return None


class ActivationService:
    @staticmethod
    def activate_user(user):
        if user:
            UserRepository.activate_user(user)
            return user
        else:
            return None

    @staticmethod
    def decode_uid(uidb64):
        return urlsafe_base64_decode(uidb64).decode()

    @staticmethod
    def send_activate_link(request, user):
        uidb64 = urlsafe_base64_encode(force_bytes(user.pk))
        send_mail(
            subject="Verify your email",
            message=request.build_absolute_uri(
                f"{reverse('activate')}?token={activation_token.make_token(user)}&uid={uidb64}"
            ),
            from_email="espada@noreply.org",
            recipient_list=[user.email],
        )


class UserService:
    @staticmethod
    def get_user_by_id(user_id):
        return UserRepository.get_user_by_id(user_id)
