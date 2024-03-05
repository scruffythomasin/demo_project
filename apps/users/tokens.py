from django.contrib.auth.tokens import PasswordResetTokenGenerator

from .models import User


class UserActivationTokenGenerator(PasswordResetTokenGenerator):
    def _make_hash_value(self, user: User, timestamp: int) -> str:
        return str(user.pk) + str(timestamp) + str(user.is_verified)


activation_token = UserActivationTokenGenerator()
