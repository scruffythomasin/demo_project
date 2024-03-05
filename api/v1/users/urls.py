from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView

from .views import (ActivateView, ChangePasswordView, LoginView, RegisterView,
                    ResendActivationView)

urlpatterns = [
    path("login/", LoginView.as_view(), name="login"),
    path("register/", RegisterView.as_view(), name="register"),
    path("refresh/", TokenRefreshView.as_view(), name="refresh"),
    path("activate/", ActivateView.as_view(), name="activate"),
    path(
        "resend-activation/", ResendActivationView.as_view(), name="resend-activation"
    ),
    # TODO: Add reset password
    path("change-password/", ChangePasswordView.as_view(), name="change-password"),
]
