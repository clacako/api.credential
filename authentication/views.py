from django.shortcuts import render
from rest_framework.views import APIView
from django.http import JsonResponse, HttpResponse
from django.core.exceptions import ObjectDoesNotExist
from datetime import datetime
from systems.cores.middleware import Authentication, Token as AuthToken
from systems.cores.error_message import error_message
from systems.validations.request import RequestData
from systems.utilities.messages import json_message, serializer_errors_to_str

# Models
from data.models import Users

# Serializers
from .serializers import (
    Login as SerializerLogin
)

class Login(APIView):
    validators_post = ["email", "secret_key"]
    
    def post(self, request, *args, **kwargs):
        client_data = RequestData(data = request.POST, validators = self.validators_post)
        if client_data.is_valid():
            serializer  = SerializerLogin(data=client_data.cleaned_data)
            if serializer.is_valid():
                user    = Authentication(
                    data            = serializer.data,
                    app_secret_key  = request.headers.get("sckey"),
                    domain          = client_data.cleaned_data.get("domains")
                )
                if user.authenticated():
                    data        = user.credential
                    response    = json_message(status=201, data=[data])
                    return JsonResponse(response, status=201)
                else:
                    response    = json_message(status=400, message=f"{user.message} <br /> CODE: AUTH_USR 201")
                    return JsonResponse(response, status=400)
            else:
                message     = serializer_errors_to_str(serializer.errors)
                response    = json_message(status=400, message=f"{message} <br /> CODE: SRLZ_USR 202")
                return JsonResponse(response, status=400)
        else:
            response    = json_message(status=400, message=f"{client_data.message} <br /> CODE: VLDN_USR 203")
            return JsonResponse(response, status=400)
        
class Token(APIView):
    validators_post = ["token"]
    
    def post(self, request, *args, **kwargs):
        client_data = RequestData(data=request.POST, validators=self.validators_post)
        if client_data.is_valid():
            user    = AuthToken(
                shortname   = request.headers.get("shortname"),
                secret_key  = request.headers.get("sckey"),
                token       = client_data.cleaned_data.get("token")
            )
            if user.granted_permission():
                data        = user.credential
                response    = json_message(status=201, data=[data])
                return JsonResponse(response, status=201)
            else:
                response    = json_message(status=400, message=f"{user.message} CODE: AUTH_TKN_USR 201")
                return JsonResponse(response, status=400)
        else:
            response    = json_message(status=400, message=f"{client_data.message} <br /> CODE: VLDN_TKN_USR 201")
            return JsonResponse(response, status=400)
        
    def put(self, request, *args, **kwargs):
        client_data = RequestData(data=request.POST, validators=self.validators_post)
        if client_data.is_valid():
            user    = AuthToken(
                shortname   = request.headers.get("shortname"),
                secret_key  = request.headers.get("sckey"),
                token       = client_data.cleaned_data.get("token")
            )
            if user.destroy():
                response    = json_message(status=201)
                return JsonResponse(response, status=201)
            else:
                response    = json_message(status=400, message=f"{user.message} <br /> CODE: AUTH_TKN_USR 301")
                return JsonResponse(response, status=400)
        else:
            response    = json_message(status=400, message=f"{client_data.message} <br /> CODE: VLDN_TKN_USR 301")
            return JsonResponse(response, status=400)