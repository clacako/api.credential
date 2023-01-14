from django.utils.deprecation import MiddlewareMixin
from django.http import JsonResponse, HttpResponse
from django.core.exceptions import ObjectDoesNotExist
from systems.cores.security import ClightCrypto, ClightHash
from systems.utilities.generate_number import Alphanumeric, Generate
from datetime import datetime, timedelta
from authentication.models import Token as ModelToken
from data.models import Applications, Domains, Users

class ClightMiddleware(MiddlewareMixin):
    def process_request(self, request):
        try:
            shortname   = request.headers.get("shortname")
            secret_key  = request.headers.get("sckey")
            host        = f"{request.scheme}://{request.META['REMOTE_ADDR']}"
            Applications.objects.get(
                shortname   = shortname,
                secret_key  = secret_key,
                host        = host,
                is_archived = 0
            )
        except:
            response    = {"status": 403, "message": "Unauthorized"}
            return JsonResponse(response, status=403)

        # response    = {"code": 200, "message": "Success", "type": "credential"}
        # return JsonResponse(response, status=200)
        
        # Save log request API
        # client_data = {
        #     "code"  : request.headers["code"],
        #     "key"   : request.headers["key"]
        # }
        
        # request_data = {
        #     "method"    : request.method,
        #     "url"       : request.path_info 
        # }
        
        # Log_Request_API.objects.create(
        #     host=request.META['REMOTE_ADDR'],
        #     client_data=client_data,
        #     request_data=request_data,
        # )

     
class Authentication():
    def __init__(self, data, app_secret_key, domain=None, *args, **kwargs):
        self.__data             = data
        self.__app_secret_key   = app_secret_key
        self.__domain           = domain

    def authenticated(self):
        try:
            email       = self.__data.get("email")
            password    = self.__data.get("secret_key")
            domain_exid = self.__domain
            # Get application
            try:
                application = Applications.objects.get(secret_key=self.__app_secret_key)
            except ObjectDoesNotExist:
                self.message    = "Application: object does not exist"
                return False
            
            # Checking domain id
            domain  = None
            if domain_exid:
                # Get domain
                try:
                    domain  = Domains.objects.get(external_id=domain_exid, applications=application.id)
                except ObjectDoesNotExist:
                    self.message    = "Domains: object does not exist"
                    return False

                # Get user
                try:
                    user    = Users.objects.get(email=email, secret_key=password, applications=application.id, domains=domain.id)
                except ObjectDoesNotExist:
                    self.message    = "User: object does not exist"
                    return False
            else:
                # Get user
                try:
                    user    = Users.objects.get(email=email, secret_key=password, applications=application.id)
                except ObjectDoesNotExist:
                    self.message    = "User: object does not exist"
                    return False
            
            role        = user.roles.filter(application=application.id).first()
        except ObjectDoesNotExist:
            self.message  = "Wrong Email Or Password"
            return False
        else:
            # Generate token
            token   = ClightHash(key=Alphanumeric(model=ModelToken).auto_generate()).hash_sha256()
            # Generate credential
            self.credential   = {
                "name"          : user.username,
                "role"          : role.name,
                "application"   : application.external_id,
                "domain"        : domain.external_id if domain else None,
                "token"         : token
            }
            # Set expiry date token
            expiry_date = datetime.now() + timedelta(days=7)  
            # Save token, credential
            ModelToken.objects.create(
                external_id     = Alphanumeric(model=ModelToken).auto_generate(),
                token           = token,
                credential      = self.credential,
                expired_date    = expiry_date
            )
            # Update
            Users.objects.filter(id=user.id).update(last_login=datetime.now())
            # Save user activity
            # Log_User_Activity.objects.create(user={"id" : user.id, "name" : user.name}, activity="Login")

            return True


class Token():    
    def __init__(self, shortname, secret_key, token):
        self.__shortname        = shortname
        self.__secret_key       = secret_key
        self.__token            = token
        self.__role_can_access  = None
        
    def granted_permission(self):
        # Get token
        try:
            token   = ModelToken.objects.get(token=self.__token, is_archived=0)
        except ObjectDoesNotExist:
            self.message    = "Token: expired"
            return False
        
        # Get application
        try:
            application = Applications.objects.get(shortname=self.__shortname, secret_key=self.__secret_key)
        except ObjectDoesNotExist:
            self.message    = "Application: does not exist"
            return False

        # Get user
        try:
            user    = Users.objects.get(username=token.credential.get("name"))
        except ObjectDoesNotExist:
            self.message    = "User: does not exist"
            return False
        
        today           = datetime.timestamp(datetime.now())
        expired_date    = datetime.timestamp(token.expired_date)
     
        # Validate expired date
        if today >= expired_date:
            # Update is archived token
            ModelToken.objects.filter(token=self.__token).update(
                is_archived     = 1,
                archived_date   = datetime.now(),
                archived_note   = "expired token",
            )
            self.message  = "Token expired, please login to continue"
            return False
        
        # Validate credential
        if token.credential.get("application") != application.external_id:  
            self.message  = "Invalid credential, please login to continue"
            return False
        
        self.credential     = token.credential
        self.user           = user
        self.application    = application
        return True
    
    def destroy(self):
        if self.granted_permission():
            # Update is archived token
            ModelToken.objects.filter(token=self.__token).update(
                is_archived     = 1,
                archived_date   = datetime.now(),
                archived_note   = "log out",
            )
        else:
            self.message    = "Invalid Credential, please login to continue"
            return False
        
        return True
    
    def authorized(self):
        if self.granted_permission():
            if self.get_credential("role") in self.__role_can_access:
                return True
            else:
                self.message    = "Unauthorized ll"
        else:
            self.message    = "Token expired, please login to continue"
            
        return False


class Destroy():
    def __init__(self, token, *args, **kwargs):
        self.__token    = token
        
    def __get_user(self):
        try:
            self.__data = ModelToken.objects.get(token=self.__token)
        except ObjectDoesNotExist:
            self.message    = "Token: object does not exist"
            return False
        else:
            return True
            
    def destroy(self):
        if self.__get_user():
            name    = self.__data.credential.get("name")
            # Update is logged in to 0
            Users.objects.filter(name=name).update(is_loggedin=0)
            # Update token is active to 0
            ModelToken.objects.filter(token=self.__token).update(is_active=0)
        