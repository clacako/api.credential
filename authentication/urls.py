from django.urls import path
from .views import *

urlpatterns = [
    path("login", Login.as_view()),
    path("token", Token.as_view())
]