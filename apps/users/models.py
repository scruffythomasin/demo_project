from django.contrib.auth.models import AbstractUser
from django.db import models


class User(AbstractUser):
    avatar = models.ImageField(upload_to="users/avatars", blank=True)
    email = models.EmailField(unique=True)
    is_verified = models.BooleanField(default=False)

    class Meta:
        ordering = ["-date_joined"]
