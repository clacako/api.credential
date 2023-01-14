from dataclasses import dataclass
from http import client
import json
from django.shortcuts import render
from rest_framework.views import APIView
from django.http import JsonResponse, HttpResponse
from django.core.exceptions import ObjectDoesNotExist
from datetime import datetime
from systems.cores.error_message import error_message
from systems.cores.middleware import Token as AuthToken
from systems.validations.request import RequestData, QueryParam
from systems.utilities.messages import json_message, serializer_errors_to_str
from systems.utilities.generate_number import Alphanumeric

# Serializers
from .serializers import (
    RoleRegister,
    Users as SerializerUsers,
    UserRegister,
    Roles as SerializerRoles,
    RoleRegister,
    RoleUpdate,
    ApplicationRegister,
    Applications as SerializerApplications,
    ApplicationSecretKey as SerializerApplicationSecretKey,
    ApplicationUpdate,
    ApplicationSetArchived,
    Domains as SerializerDomains,
    DomainRegister,
)

# Models
from .models import(
    Users as ModelUsers,
    Roles as ModelRoles,
    Applications as ModelApplications,
    Domains as ModelDomains,
)



# Users
class Users(APIView):
    validators_post  = [
        "roles",
        "applications",
        "secret_key",
        "firstname",
        "email",
        "phone_number",
        "address",
    ]
    
    def post(self, request, *args, **kwargs):
        client_data     = RequestData(
            data        = request.POST, 
            validators  = self.validators_post,
            relation    = True,
            fields      = ["roles", "applications", "domains"],
            models      = ModelUsers
        )
        if client_data.is_valid():
            serializer   = UserRegister(data=client_data.cleaned_data)
            if serializer.is_valid():
                data        = serializer.save()
                response    = json_message(status=201, data=[{"external_id" : data.external_id}])
                return JsonResponse(response, status=201)
            else:
                message     = serializer_errors_to_str(serializer.errors)
                response    = json_message(status=400, message=f"{message} <br /> CODE: SRLZ_USR 201")
                return JsonResponse(response, status=400)
        else:
            response    = json_message(status=400, message=f"{client_data.message} <br /> CODE: VLDN_USR 202")
            return JsonResponse(response, status=400)


# Roles
class Roles(APIView):
    validators_post = ["name", "application"]
    validators_put  = ["external_id"]
    
    def post(self, request, *args, **kwargs):
        token    = AuthToken(
            shortname   = request.headers.get("shortname"),
            secret_key  = request.headers.get("sckey"),
            token       = request.GET.get("auth")
        )
        if token.granted_permission():
            client_data = RequestData(
                data        = request.POST,
                validators  = self.validators_post,
                relation    = True,
                fields      = ["application"],
                models      = ModelRoles
            )
            if client_data.is_valid():
                initial     = {"application" : client_data.cleaned_data.get("application")}
                serializer  = RoleRegister(data=client_data.cleaned_data, initial=initial)
                if serializer.is_valid():
                    data        = serializer.save()
                    response    = json_message(status=200, data=[{"external_id" : data.external_id}])
                    return JsonResponse(response, status=200)
                else:
                    message     = serializer_errors_to_str(serializer.errors)
                    response    = json_message(status=400, message=f"{message} <br /> CODE: ROLE_SRLZ 201")
                    return JsonResponse(response, status=400)
            else:
                response    = json_message(status=400, message=f"{client_data.message} <br /> CODE: ROLE_VLDN 202")
                return JsonResponse(response, status=400)
        else:
            response    = json_message(status=400, message=f"{token.message} <br /> CODE: ROLE_AUTH 203")
            return JsonResponse(response, status=400)

    def put(self, request, *args, **kwargs):
        token    = AuthToken(
            shortname   = request.headers.get("shortname"),
            secret_key  = request.headers.get("sckey"),
            token       = request.GET.get("auth")
        )
        if token.granted_permission():
            client_data = RequestData(
                data        = request.POST,
                validators  = self.validators_put,
                relation    = True,
                fields      = ["application"],
                models      = ModelRoles
            )
            if client_data.is_valid():
                initial     = {
                    "external_id"   : client_data.cleaned_data.get("external_id"), 
                    "application"   : client_data.cleaned_data.get("application")
                }
                serializer  = RoleRegister(data=client_data.cleaned_data, initial=initial)
                if serializer.is_valid():
                    data        = serializer.save()
                    response    = json_message(status=200, data=[{"external_id" : data.external_id}])
                    return JsonResponse(response, status=200)
                else:
                    message     = serializer_errors_to_str(serializer.errors)
                    response    = json_message(status=400, message=f"{message} <br /> CODE: ROLE_SRLZ 301")
                    return JsonResponse(response, status=400)
            else:
                response    = json_message(status=400, message=f"{client_data.message} <br /> CODE: ROLE_VLDN 302")
                return JsonResponse(response, status=400)
        else:
            response    = json_message(status=400, message=f"{token.message} <br /> CODE: ROLE_AUTH 303")
            return JsonResponse(response, status=400)

class RoleDetail(APIView):
    validators_post = ["name", "application"]
    validators_put  = ["external_id"]
    
    def get(self, request, *args, **kwargs):
        token    = AuthToken(
            shortname   = request.headers.get("shortname"),
            secret_key  = request.headers.get("sckey"),
            token       = request.GET.get("auth")
        )
        if token.granted_permission():
            # Get role detail
            try:
                external_id = kwargs.get("role_exid")
                role        = ModelRoles.objects.get(external_id=external_id)
            except ObjectDoesNotExist:
                response    = json_message(400, message=f"Role: object does not exist <br /> CODE: ODE_ROLEDTL 101")
                return JsonResponse(response, status=400)
            else:
                serializer  = RoleUpdate([role], many=True)
                response    = json_message(status=200, data=serializer.data[0])
                return JsonResponse(response, status=200)
        else:
            response    = json_message(status=400, message=f"{token.message} <br /> CODE: AUTH_ROLEDTL 102")
            return JsonResponse(response, status=400)
        
    def put(self, request, *args, **kwargs):
        token    = AuthToken(
            shortname   = request.headers.get("shortname"),
            secret_key  = request.headers.get("sckey"),
            token       = request.GET.get("auth")
        )
        if token.granted_permission():
            client_data = RequestData(
                data        = request.data,
                validators  = self.validators_put,
                relation    = True,
                fields      = ["application"],
                models      = ModelRoles
            )
            if client_data.is_valid():
                # Get role
                try:
                    external_id = client_data.cleaned_data.get("external_id")
                    role        = ModelRoles.objects.get(external_id=external_id)
                except ObjectDoesNotExist:
                    response    = json_message(400, message=f"Role: object does not exist <br /> CODE: ROLE_ODE 301")
                    return JsonResponse(response, status=400)
                else:
                    initial     = {
                        "external_id"   : role.external_id,
                        "application"   : role.application
                    }
                    serializer  = RoleUpdate(role, data=client_data.cleaned_data, initial=initial)
                    if serializer.is_valid():
                        data        = serializer.save()
                        response    = json_message(status=200, data={"external_id" : data.external_id})
                        return JsonResponse(response, status=200)
                    else:
                        message     = serializer_errors_to_str(serializer.errors)
                        response    = json_message(status=400, message=f"{message} <br /> CODE: ROLE_SRLZ 302")
                        return JsonResponse(response, status=400)
            else:
                response    = json_message(status=400, message=f"{client_data.message} <br /> CODE: ROLE_VLDN 303")
                return JsonResponse(response, status=400)
        else:
            response    = json_message(status=400, message=f"{token.message} <br /> CODE: ROLE_AUTH 304")
            return JsonResponse(response, status=400)
             

# Applications
class Applications(APIView):
    validators_post = ["host", "shortname", "email", "description"]
    validators_put  = ["external_id"]
    
    def get(self, request, *args, **kwargs):
        token    = AuthToken(
            shortname   = request.headers.get("shortname"),
            secret_key  = request.headers.get("sckey"),
            token       = request.GET.get("auth")
        )
        if token.granted_permission():
            # Get user role
            user        = token.user
            user_roles  = user.roles.filter(name="administrator")
            # Collect application id from user roles
            application_id  = [role.application.id for role in user_roles] if user_roles.exists() else []
            # Get appications
            user_applications   = token.user.applications.filter(id__in=application_id).order_by("-id")
            serializer          = SerializerApplications(user_applications, many=True)
            
            response    = json_message(200, data=serializer.data)
            return JsonResponse(response, status=200)
        else:
            response    = json_message(status=400, message=f"{token.message} <br /> CODE: VLDN_APP 102")
            return JsonResponse(response, status=400)
                
    def post(self, request, *args, **kwargs):
        token    = AuthToken(
            shortname   = request.headers.get("shortname"),
            secret_key  = request.headers.get("sckey"),
            token       = request.GET.get("auth")
        )
        if token.granted_permission():
            client_data = RequestData(data=request.POST, validators=self.validators_post)
            if client_data.is_valid():
                serializer  = ApplicationRegister(data=client_data.cleaned_data)
                if serializer.is_valid():
                    # Save application
                    application = serializer.save()
                    
                    # Save administrator user role
                    user    = token.user
                    role    = ModelRoles.objects.create(
                        created_by  = user.username,
                        external_id = Alphanumeric(model=ModelRoles).auto_generate(),
                        name        = "administrator",
                        application = application
                    )
                    
                    # Adding user to application and adding user as administrator on new application
                    user.applications.add(application)
                    user.roles.add(role)
                    
                    response    = json_message(status=200, data=[{"external_id" : application.external_id}])
                    return JsonResponse(response, status=200)
                else:
                    message     = serializer_errors_to_str(serializer.errors)
                    response    = json_message(status=400, message=f"{message} <br /> CODE: SRLZ 202")
                    return JsonResponse(response, status=400)
            else:
                response    = json_message(status=400, message=f"{client_data.message} <br /> CODE: VLDN 203")
                return JsonResponse(response, status=400)
        else:
            response    = json_message(status=400, message=f"{token.message} <br /> CODE: AUTH 204")
            return JsonResponse(response, status=400)
        
class ApplicationDetails(APIView):
    validators_post = ["host", "shortname", "email", "description"]
    validators_put  = ["external_id"]
    
    def get(self, request, *args, **kwargs):
        token    = AuthToken(
            shortname   = request.headers.get("shortname"),
            secret_key  = request.headers.get("sckey"),
            token       = request.GET.get("auth")
        )
        if token.granted_permission():
            # Get application
            try:
                external_id = kwargs.get("application_exid")
                application = ModelApplications.objects.get(external_id=external_id)
            except ObjectDoesNotExist:
                response    = json_message(400, message=f"Application: object does not exist <br /> CODE: ODE_APPDTL 101")
                return JsonResponse(response, status=400)
            else:
                serializer  = SerializerApplications([application], many=True)
                response    = json_message(status=200, data=serializer.data[0])
                return JsonResponse(response, status=200)
        else:
            response    = json_message(status=400, message=f"{token.message} <br /> CODE: AUTH_APPDTL 102")
            return JsonResponse(response, status=400)
    
    def put(self, request, *args, **kwargs):
        token    = AuthToken(
            shortname   = request.headers.get("shortname"),
            secret_key  = request.headers.get("sckey"),
            token       = request.GET.get("auth")
        )
        if token.granted_permission():
            client_data = RequestData(data=request.data, validators=self.validators_put)
            if client_data.is_valid():
                # Get application
                try:
                    external_id = client_data.cleaned_data.get("external_id")
                    application = ModelApplications.objects.get(external_id=external_id)
                except ObjectDoesNotExist:
                    response    = json_message(400, message=f"Application: object does not exist <br /> CODE: ODE 301")
                    return JsonResponse(response, status=400)
                else:
                    initial     = {"external_id" : external_id}
                    serializer  = ApplicationUpdate(application, data=client_data.cleaned_data, initial=initial)
                    if serializer.is_valid():
                        data        = serializer.save()
                        response    = json_message(status=200, data={"external_id" : data.external_id})
                        return JsonResponse(response, status=200)
                    else:
                        message     = serializer_errors_to_str(serializer.errors)
                        response    = json_message(status=400, message=f"{message} <br /> CODE: SRLZ 302")
                        return JsonResponse(response, status=400)
            else:
                response    = json_message(status=400, message=f"{client_data.message} <br /> CODE: VLDN 303")
                return JsonResponse(response, status=400)
        else:
            response    = json_message(status=400, message=f"{token.message} <br /> CODE: AUTH 304")
            return JsonResponse(response, status=400)
    
    def delete(self, request, *args, **kwargs):
        token    = AuthToken(
            shortname   = request.headers.get("shortname"),
            secret_key  = request.headers.get("sckey"),
            token       = request.GET.get("auth")
        )
        if token.granted_permission():
            client_data = RequestData(data=request.data, validators=self.validators_put)
            if client_data.is_valid():
                # Get application
                try:
                    external_id = client_data.cleaned_data.get("external_id")
                    application = ModelApplications.objects.get(external_id=external_id, is_archived=0)
                except ObjectDoesNotExist:
                    response    = json_message(400, message=f"Application: object does not exist <br /> CODE: ODE 401")
                    return JsonResponse(response, status=400)
                else:
                    initial     = {"username" : token.user.username}
                    serializer  = ApplicationSetArchived(application, data=client_data.cleaned_data, initial=initial)
                    if serializer.is_valid():
                        data        = serializer.save()
                        response    = json_message(status=200, data=[{"external_id" : data.external_id}])
                        return JsonResponse(response, status=200)
                    else:
                        message     = serializer_errors_to_str(serializer.errors)
                        response    = json_message(status=400, message=f"{message} <br /> CODE: SRLZ 402")
                        return JsonResponse(response, status=400)
            else:
                response    = json_message(status=400, message=f"{client_data.message} <br /> CODE: VLDN 403")
                return JsonResponse(response, status=400)
        else:
            response    = json_message(status=400, message=f"{token.message} <br /> CODE: AUTH 404")
            return JsonResponse(response, status=400)

class ApplicationSecretKey(APIView):
    validators_put  = ["external_id", "secret_key"]
    
    def get(self, request, *args, **kwargs):
        token    = AuthToken(
            shortname   = request.headers.get("shortname"),
            secret_key  = request.headers.get("sckey"),
            token       = request.GET.get("auth")
        )
        if token.granted_permission():
            # Get application
            try:
                external_id = kwargs.get("application_exid")
                application = ModelApplications.objects.get(external_id=external_id)
            except ObjectDoesNotExist:
                response    = json_message(400, message=f"Application: object does not exist <br /> CODE: ODE_APPDTL 101")
                return JsonResponse(response, status=400)
            else:
                serializer  = SerializerApplicationSecretKey([application], many=True)
                response    = json_message(status=200, data=serializer.data[0])
                return JsonResponse(response, status=200)
        else:
            response    = json_message(status=400, message=f"{token.message} <br /> CODE: AUTH_APPDTL 102")
            return JsonResponse(response, status=400)
        
    def put(self, request, *args, **kwargs):
        token    = AuthToken(
            shortname   = request.headers.get("shortname"),
            secret_key  = request.headers.get("sckey"),
            token       = request.GET.get("auth")
        )
        if token.granted_permission():
            client_data = RequestData(data=request.data, validators=self.validators_put)
            if client_data.is_valid():
                # Get application
                try:
                    external_id = client_data.cleaned_data.get("external_id")
                    application = ModelApplications.objects.get(external_id=external_id)
                except ObjectDoesNotExist:
                    response    = json_message(400, message=f"Application: object does not exist <br /> CODE: ODE 301")
                    return JsonResponse(response, status=400)
                else:
                    serializer  = SerializerApplicationSecretKey(application, data=client_data.cleaned_data)
                    if serializer.is_valid():
                        data        = serializer.save()
                        response    = json_message(status=200, data={"external_id" : data.external_id})
                        return JsonResponse(response, status=200)
                    else:
                        message     = serializer_errors_to_str(serializer.errors)
                        response    = json_message(status=400, message=f"{message} <br /> CODE: SRLZ 302")
                        return JsonResponse(response, status=400)
            else:
                response    = json_message(status=400, message=f"{client_data.message} <br /> CODE: VLDN 303")
                return JsonResponse(response, status=400)
        else:
            response    = json_message(status=400, message=f"{token.message} <br /> CODE: AUTH 304")
            return JsonResponse(response, status=400)
            
class ApplicationRoles(APIView):
    validators_put  = ["external_id", "application"]
    
    def get(self, request, *args, **kwargs):
        token    = AuthToken(
            shortname   = request.headers.get("shortname"),
            secret_key  = request.headers.get("sckey"),
            token       = request.GET.get("auth")
        )
        if token.granted_permission():
            # Get application
            try:
                external_id = kwargs.get("application_exid") 
                application = ModelApplications.objects.get(external_id=external_id)
            except ObjectDoesNotExist:
                response    = json_message(400, message=f"Application: object does not exist <br /> CODE: ODE 101")
                return JsonResponse(response, status=400)
            else:
                roles       = ModelRoles.objects.filter(application=application)
                serializer  = SerializerRoles(roles, many=True)
                response    = json_message(status=200, data=serializer.data)
                return JsonResponse(response, status=200)
        else:
            response    = json_message(status=400, message=f"{token.message} <br /> CODE: VLDN_APP 102")
            return JsonResponse(response, status=400)
        
class ApplicationUsers(APIView):
    validators_post  = [
        "roles",
        "applications",
        "secret_key",
        "firstname",
        "email",
        "phone_number",
        "address",
    ]
    
    def get(self, request, *args, **kwargs):
        token   = AuthToken(
            shortname   = request.headers.get("shortname"),
            secret_key  = request.headers.get("sckey"),
            token       = request.GET.get("auth")
        )
        if token.granted_permission():
            # Get application
            try:
                external_id = kwargs.get("application_exid") 
                application = ModelApplications.objects.get(external_id=external_id)
            except ObjectDoesNotExist:
                response    = json_message(400, message=f"Application: object does not exist <br /> CODE: ODE_APPUSR 101")
                return JsonResponse(response, status=400)
            else:
                users       = ModelUsers.objects.filter(applications=application).order_by("-id")
                serializer  = SerializerUsers(users, many=True)
                response    = json_message(200, data=serializer.data)
                return JsonResponse(response, status=200)
        else:
            response    = json_message(status=400, message=f"{token.message} <br /> CODE: VLDN_APPUSR 102")
            return JsonResponse(response, status=400)

    def post(self, request, *args, **kwargs):
        token   = AuthToken(
            shortname   = request.headers.get("shortname"),
            secret_key  = request.headers.get("sckey"),
            token       = request.GET.get("auth")
        )
        if token.granted_permission():
            client_data = RequestData(
                data        = request.POST,
                validators  = self.validators_post,
                relation    = True,
                fields      = ["roles", "applications", "domains"],
                models      = ModelUsers
            )
            if client_data.is_valid():
                serializer  = UserRegister(data=client_data.cleaned_data)
                if serializer.is_valid():
                    data    = serializer.save()
                    response    = json_message(status=200, data=[{"external_id" : data.external_id}])
                    return JsonResponse(response, status=200)
                else:
                    message     = serializer_errors_to_str(serializer.errors)
                    response    = json_message(status=400, message=f"{message} <br /> CODE: SRLZ 201")
                    return JsonResponse(response, status=400)
            else:
                response    = json_message(status=400, message=f"{client_data.message} <br /> CODE: VLDN 202")
                return JsonResponse(response, status=400)
        else:
            response    = json_message(status=400, message=f"{token.message} <br /> CODE: AUTH 203")
            return JsonResponse(response, status=400)
    
class ApplicationDomains(APIView):
    def get(self, request, *args, **kwargs):
        token    = AuthToken(
            shortname   = request.headers.get("shortname"),
            secret_key  = request.headers.get("sckey"),
            token       = request.GET.get("auth")
        )
        if token.granted_permission():
            try:
                external_id = kwargs.get("application_exid") 
                application = ModelApplications.objects.get(external_id=external_id)
            except ObjectDoesNotExist:
                response    = json_message(400, message=f"Application: object does not exist <br /> CODE: ODE 101")
                return JsonResponse(response, status=400)
            else:
                domains     = ModelDomains.objects.filter(applications=application.id).order_by("-id")
                serializer  = SerializerDomains(domains, many=True)
                response    = json_message(200, data=serializer.data)
                return JsonResponse(response, status=200)
        else:
            response    = json_message(status=400, message=f"{token.message} <br /> CODE: VLDN_APP 102")
            return JsonResponse(response, status=400)

class ApplicationDomainUsers(APIView):
    def get(self, request, *args, **kwargs):
        token   = AuthToken(
            shortname   = request.headers.get("shortname"),
            secret_key  = request.headers.get("sckey"),
            token       = request.GET.get("auth")
        )
        if token.granted_permission():
            # Get application
            try:
                application = ModelApplications.objects.get(external_id=kwargs.get("application_exid")) 
            except ObjectDoesNotExist:
                response    = json_message(400, message=f"Application: object does not exist <br /> CODE: ODE_APPDMN 101")
                return JsonResponse(response, status=400)
            
            # Get domain
            try:
                domain  = ModelDomains.objects.get(external_id=kwargs.get("domain_exid")) 
            except ObjectDoesNotExist:
                response    = json_message(400, message=f"Domain: object does not exist <br /> CODE: ODE_APPDMN 102")
                return JsonResponse(response, status=400)
            
            # Check the request has a parameters
            if len(request.GET) > 1:
                parameters  = QueryParam(data=request.GET, relation=True, model=ModelUsers)
                if parameters.is_valid():
                    users       = ModelUsers.objects.filter(applications=application, domains=domain.id, **parameters.cleaned_data)
                else:
                    response    = json_message(400, message=parameters.error)
                    return JsonResponse(response, status=400)
            else:
                users       = ModelUsers.objects.filter(applications=application.id, domains=domain.id)
            
            serializer  = SerializerUsers(users, many=True)
            response    = json_message(200, data=serializer.data)
            return JsonResponse(response, status=200)
        else:
            response    = json_message(status=400, message=f"{token.message} <br /> CODE: VLDN_APPDMN 103")
            return JsonResponse(response, status=400)

class ApplicationDomainDetails(APIView):
    def get(self, request, *args, **kwargs):
        token    = AuthToken(
            shortname   = request.headers.get("shortname"),
            secret_key  = request.headers.get("sckey"),
            token       = request.GET.get("auth")
        )
        if token.granted_permission():
            # Get application
            try:
                external_id  = kwargs.get("application_exid")
                application  = ModelApplications.objects.get(external_id=external_id)
            except ObjectDoesNotExist:
                response    = json_message(400, message=f"Application: object does not exist <br /> CODE: ODE_APPDMNDTL 101")
                return JsonResponse(response, status=400)
            else:
                # Get domain
                try:
                    external_id = kwargs.get("domain_exid")
                    domain      = ModelDomains.objects.get(external_id=external_id, applications=application)
                except ObjectDoesNotExist:
                    response    = json_message(400, message=f"Domain: object does not exist <br /> CODE: ODE_APPDMNDTL 102")
                    return JsonResponse(response, status=400)
                else:
                    serializer  = SerializerDomains([domain], many=True)
                    response    = json_message(status=200, data=serializer.data[0])
                    return JsonResponse(response, status=200)
        else:
            response    = json_message(status=400, message=f"{token.message} <br /> CODE: AUTH_APPDMNDTL 102")
            return JsonResponse(response, status=400)

    
# Domains
class Domains(APIView):
    validators_post = ["name", "url_name", "applications"]
      
    def post(self, request, *args, **kwargs):
        token    = AuthToken(
            shortname   = request.headers.get("shortname"),
            secret_key  = request.headers.get("sckey"),
            token       = request.GET.get("auth")
        )
        if token.granted_permission():
            client_data = RequestData(
                data        = request.POST,
                validators  = self.validators_post,
                relation    = True,
                fields      = ["applications"],
                models      = ModelDomains
            )
            if client_data.is_valid():
                serializer  = DomainRegister(data=client_data.cleaned_data)
                if serializer.is_valid():
                    data    = serializer.save()
                    response    = json_message(status=200, data={"external_id" : data.external_id})
                    return JsonResponse(response, status=200)
                else:
                    message     = serializer_errors_to_str(serializer.errors)
                    response    = json_message(status=400, message=f"{message} <br /> CODE: SRLZ 201")
                    return JsonResponse(response, status=400)
            else:
                response    = json_message(status=400, message=f"{client_data.message} <br /> CODE: VLDN 202")
                return JsonResponse(response, status=400)
        else:
            response    = json_message(status=400, message=f"{token.message} <br /> CODE: AUTH 203")
            return JsonResponse(response, status=400)

class DomainDetails(APIView):
    pass