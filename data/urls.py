from django.urls import path
from .views import *

urlpatterns = [
    path("users", Users.as_view()),
    path("roles", Roles.as_view()),
    path("roles/<int:role_exid>", RoleDetail.as_view()),
    path("applications", Applications.as_view()),
    path("application/<int:application_exid>", ApplicationDetails.as_view()),
    path("application/<int:application_exid>/secretKey", ApplicationSecretKey.as_view()),
    path("application/<int:application_exid>/roles", ApplicationRoles.as_view()),
    path("application/<int:application_exid>/users", ApplicationUsers.as_view()),
    path("application/<int:application_exid>/domains", ApplicationDomains.as_view()),
    path("application/<int:application_exid>/domain/<int:domain_exid>", ApplicationDomainDetails.as_view()),
    path("application/<int:application_exid>/domain/<domain_exid>/users", ApplicationDomainUsers.as_view()),
    path("domains", Domains.as_view()),
]