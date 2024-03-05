from django.contrib.auth import get_user_model
from django.db import IntegrityError


class UserRepository:
    @staticmethod
    def create_user(data):
        try:
            username = data.get("username")
            email = data.get("email")
            password = data.pop("password")
            user = get_user_model().objects.create_user(
                username=username, email=email, password=password
            )
            return user
        except IntegrityError:
            return None

    @staticmethod
    def get_user_by_username(username):
        return get_user_model().objects.filter(username=username).first()

    @staticmethod
    def get_user_by_email(email):
        return get_user_model().objects.filter(email=email).first()

    @staticmethod
    def activate_user(user):
        user.is_active = True
        user.is_verified = True
        user.save()

    @staticmethod
    def get_user_by_id(user_id):
        return get_user_model().objects.filter(id=user_id).first()
