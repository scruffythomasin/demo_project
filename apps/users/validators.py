from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _

from .tokens import activation_token

User = get_user_model()


# TODO: add typing to all methods
class Validator:
    """
    Base class for all validators in users app
    errors: dict
    attrs: dict from serializer (attrs)
    """

    def __init__(self, attrs):
        self.attrs = attrs
        self.errors = {}

    def _add_error(self, field_name, message):
        if field_name not in self.errors:
            self.errors[field_name] = []
        self.errors[field_name].append(_(message))

    def is_valid(self):
        if self.errors:
            raise ValidationError(self.errors)
        return self.attrs


class AuthValidator(Validator):
    def validate_field_length(self, field_name, min_length):
        field_value = self.attrs.get(field_name)
        if field_value and len(field_value) < min_length:
            self._add_error(
                field_name,
                f"{field_name.capitalize()} must be at least {min_length} characters long",
            )

    def validate_alphanumeric(self, field_name):
        field_value = self.attrs.get(field_name)
        if field_value and not field_value.isalnum():
            self._add_error(
                field_name, f"{field_name.capitalize()} must be alphanumeric"
            )

    def validate_special_char(self, field_name):
        field_value = self.attrs.get(field_name)
        if field_value and field_value.isalnum():
            self._add_error(
                field_name, f"{field_name.capitalize()} must have special character"
            )

    def validate(self):
        raise NotImplementedError


class LoginValidator(AuthValidator):
    def validate_exists(self, model, field_name: str, **kwargs):
        if not model.objects.filter(**kwargs).exists():
            self._add_error(
                field_name=field_name,
                message=f"{model.__name__.capitalize()} does not exist",
            )
        return model.objects.filter(**kwargs).first()

    def check_password(self, user, password):
        if not user.check_password(password):
            self._add_error("password", "Incorrect password")

    def validate(self):
        username = self.attrs.get("username")
        password = self.attrs.get("password")
        user = self.validate_exists(User, "username", username=username)
        if user:
            self.check_password(user, password)
        return self.is_valid()


class RegisterValidator(AuthValidator):
    def validate_not_exists(self, model, field_name, **kwargs):
        if model.objects.filter(**kwargs).exists():
            self._add_error(field_name, f"{field_name.capitalize()} already exists")

    def validate_confirm_password(self, password, confirm_password):
        if password != confirm_password:
            self._add_error("password", "Passwords do not match")

    def validate(self):
        self.validate_field_length("username", 5)
        self.validate_alphanumeric("username")
        self.validate_not_exists(User, "username", username=self.attrs.get("username"))
        self.validate_field_length("password", 8)
        self.validate_special_char("password")
        self.validate_not_exists(User, "email", email=self.attrs.get("email"))
        self.validate_confirm_password(
            self.attrs.get("password"), self.attrs.get("confirm_password")
        )
        return self.is_valid()


class ResetPasswordValidator(AuthValidator):
    def validate(self):
        self.validate_field_length("password", 8)
        self.validate_special_char("password")
        self.validate_confirm_password(
            self.attrs.get("password"), self.attrs.get("confirm_password")
        )
        return self.is_valid()


class ActivationTokenValidator(Validator):
    def validate(self):
        user = User.objects.filter(id=self.attrs.get("id")).first()
        if (
            not activation_token.check_token(user, self.attrs.get("token"))
            and not user is None
        ):
            self._add_error("token", "Invalid token")
        return self.is_valid()
