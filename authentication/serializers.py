from rest_framework import serializers
from datetime import datetime
from django.core.exceptions import ObjectDoesNotExist
from systems.validations.forms import PhoneNumber, SpecialChar
from systems.cores.security import ClightHash
from systems.utilities.generate_number import Alphanumeric, Generate
import re

# Models
from data.models import Domains, Users

class Login(serializers.ModelSerializer):
    class Meta:
        model   = Users
        fields  = ["email", "secret_key"]
    
    def validate_email(self, email):
        if not email:
            raise serializers.ValidationError("Must not be empty")
        
        try:
            user    = Users.objects.get(email=email)
        except ObjectDoesNotExist:
            raise serializers.ValidationError("not exist")
        
        return email
    
    def validate_secret_key(self, secret_key):
        if not secret_key:
            raise serializers.ValidationError("Password must not be empty")
        
        return ClightHash(key=secret_key).hash_sha256()