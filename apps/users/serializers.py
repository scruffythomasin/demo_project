from django.core.exceptions import ValidationError
from django.db.transaction import atomic
from rest_framework import serializers

from .services import ActivationService, LoginService, RegistrationService
from .validators import (ActivationTokenValidator, LoginValidator,
                         RegisterValidator, ResetPasswordValidator)


class LoginUserSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField()
    access_token = serializers.CharField(read_only=True)
    refresh_token = serializers.CharField(read_only=True)

    def validate(self, attrs):
        validator = LoginValidator(attrs)
        validator.validate()
        if validator.is_valid:
            return attrs
        raise ValidationError(validator.errors)


class RegisterUserSerializer(serializers.Serializer):
    username = serializers.CharField()
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)
    confirm_password = serializers.CharField(write_only=True)
    access_token = serializers.CharField(read_only=True)
    refresh_token = serializers.CharField(read_only=True)

    def validate(self, attrs):
        validator = RegisterValidator(attrs)
        return validator.validate()

    @atomic
    def create(self, validated_data):
        data, user = RegistrationService.register_user(data=validated_data)
        if data is not None:
            ActivationService.send_activate_link(
                request=self.context.get("request"), user=user
            )
            return data
        raise ValidationError("Error occurred while creating user")


class ActivateUserSerializer(serializers.Serializer):
    id = serializers.IntegerField(write_only=True)
    token = serializers.CharField(write_only=True)

    def validate(self, attrs):
        return ActivationTokenValidator(attrs).validate()

    def update(self, instance, validated_data):
        return ActivationService.activate_user(instance)


# TODO: Refactor this (move to profile app)
class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(write_only=True)
    new_password = serializers.CharField(write_only=True)
    confirm_password = serializers.CharField(write_only=True)

    def validate(self, attrs):
        validator = ResetPasswordValidator(attrs)
        return validator.validate()

    def update(self, instance, validated_data):
        instance.set_password(validated_data.get("new_password"))
        instance.save()
        return instance
