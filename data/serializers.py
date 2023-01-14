from rest_framework import serializers
from datetime import datetime
from systems.validations.forms import PhoneNumber, SpecialChar
from systems.cores.security import ClightHash
from systems.utilities.generate_number import Alphanumeric, Generate
import re

# Model
from .models import (
    Users as ModelUsers,
    Applications as ModelApplications,
    Roles as ModelRoles,
    Domains as ModelDomains,
)


# Users
class Users(serializers.ModelSerializer):
    class Meta:
        model   = ModelUsers
        fields  = [
            "created",
            "external_id",
            "id_card_type",
            "id_card_number",
            "username",
            "firstname",
            "lastname",
            "place_of_birth",
            "birthdate",
            "status",
            "gender",
            "religion",
            "email",
            "address",
            "district",
            "sub_district",
            "phone_number",
            "last_login"
        ]
        
class UserRegister(serializers.ModelSerializer):
    class Meta:
        model   = ModelUsers
        fields  = [
            "external_id",
            "roles",
            "applications",
            "domains",
            "id_card_type",
            "id_card_number",
            "username",
            "firstname",
            "lastname",
            "place_of_birth",
            "birthdate", 
            "status",
            "gender",
            "religion",
            "email",
            "address",
            "district",
            "sub_district",
            "phone_number",
            "secret_key",
        ]
        
    def validate(self, data):
        data["external_id"] = Alphanumeric(model=ModelUsers).auto_generate()
        data["username"]    = Generate(length=11).run()
        return data
        
    # def validate_username(self, username):
    #     user    = ModelUsers.objects.filter(username=username)
    #     if user.exists():
    #         raise serializers.ValidationError("already exist")
        
    #     username    = Generate(length=11).run()
    #     print(username)
    #     return username
        
    def validate_firstname(self, firstname):
        if not firstname:
            raise serializers.ValidationError("must not be empty")
        
        return firstname.strip().lower()
        
    def validate_lastname(self, lastname):
        return lastname.lower().strip() if lastname or lastname is not None else lastname
    
    def validate_place_of_birth(self, place_of_birth):
        return place_of_birth.lower().strip() if place_of_birth or place_of_birth is not None else place_of_birth
    
    def validate_birthdate(self, birthdate):
        return birthdate
    
    def validate_status(self, status):
        return status.lower().strip() if status or status is not None else status
    
    def validate_gender(self, gender):
        return gender.lower().strip() if gender or gender is not None else gender
    
    def valdiate_religion(self, religion):
        return religion.lower().strip() if religion or religion is not None else religion
    
    def validate_email(self, email):
        user    = ModelUsers.objects.filter(email=email)
        
        if not email:
            raise serializers.ValidationError("must not be empty")
        
        if user.exists():
            raise serializers.ValidationError("already exist")
        
        return email
    
    def validate_address(self, address):
        return address.lower().strip() if address or address is not None else address
    
    def validate_district(self, district):
        return district.lower().strip() if district or district is not None else district
    
    def validate_sub_district(self, sub_district):
        return sub_district.lower().strip() if sub_district or sub_district is not None else sub_district
    
    def validate_phone_number(self, phone_number):
        if not phone_number:
            raise serializers.ValidationError("must not be empty")
        
        if not phone_number.isnumeric():
            raise serializers.ValidationError("Wrong Format")
        
        phone_number    = PhoneNumber(phone_number=phone_number).cleaned_data
        user            = ModelUsers.objects.filter(phone_number=phone_number)
        
        if user.exists():
            raise serializers.ValidationError("Phone number already exist")
        
        return PhoneNumber(phone_number=phone_number).cleaned_data
    
    def validate_secret_key(self, secret_key):
        if not secret_key:
            raise serializers.ValidationError("Password must not be empty")
        
        return ClightHash(key=secret_key).hash_sha256()


# Roles
class Roles(serializers.ModelSerializer):
    class Meta:
        model   = ModelRoles
        # fields  = ["created", "external_id", "name", "application"]
        fields  = ["created", "external_id", "name"]

class RoleRegister(serializers.ModelSerializer):
    class Meta:
        model   = ModelRoles
        fields  = ["external_id", "name", "application"]
        
    def validate(self, data):
        data["external_id"] = Alphanumeric(model=ModelUsers).auto_generate()
        return data
    
    def validate_name(self, name):
        if not name:
            raise serializers.ValidationError("Must not be empty")
        
        role    = ModelRoles.objects.filter(name=name, application=self.initial.get("application"))
        if role.exists():
            raise serializers.ValidationError("Already exist")
        
        return name.strip().lower()
    
class RoleUpdate(serializers.ModelSerializer):
    class Meta:
        model   = ModelRoles
        fields  = [
            "created",
            "external_id",
            "application",
            "name",
        ]
        
    def validate(self, data):
        data["external_id"] = Alphanumeric(model=ModelUsers).auto_generate()
        return data
    
    def validate_name(self, name):
        if not name:
            raise serializers.ValidationError("Must not be empty")
        
        role    = ModelRoles.objects.filter(name=name, application=self.initial.get("application")).exclude(external_id=self.initial.get("external_id"))
        if role.exists():
            raise serializers.ValidationError("Already exist")
        
        return name.strip().lower()

# Applications
class Applications(serializers.ModelSerializer):
    class Meta:
        model   = ModelApplications
        fields  = [
            "external_id",
            "created",
            "created_by",
            "host",
            "shortname",
            "description",
            "email",
            "is_archived",
            "archived_date",
            "archived_by",
            "archived_note"
        ]

class ApplicationRegister(serializers.ModelSerializer):
    class Meta:
        model   =  ModelApplications
        fields  = [
            "external_id",
            "created_by",
            "host",
            "shortname",
            "description",
            "email",
            "secret_key",
        ]
    
    def validate(self, data):
        data["external_id"] = Alphanumeric(model=ModelUsers).auto_generate()
        data["secret_key"]  = Generate(length=15).run()
        return data
    
    def validate_host(self, host):
        if not host:
            raise serializers.ValidationError("Must not be empty")
        
        return host
    
    def validate_shortname(self, shortname):
        if not shortname:
            raise serializers.ValidationError("must not be empty")
        
        input_shortname =  SpecialChar(text=shortname)
        if not input_shortname.is_valid():
            raise serializers.ValidationError("only alphanumeric! special character or whitespace not allowed")
        
        application = ModelApplications.objects.filter(shortname=shortname)
        if application.exists():
            raise serializers.ValidationError("Shortname already exist")
        
        return shortname.lower().strip()
    
    def validate_description(self, description):
        return description.lower().strip() if description else description
    
    def validate_email(self, email):
        if not email:
            raise serializers.ValidationError("Email must not be empty")
        
        application = ModelApplications.objects.filter(email=email)
        if application.exists():
            raise serializers.ValidationError("Email already exist")
        
        return email

class ApplicationUpdate(serializers.ModelSerializer):
    class Meta:
        model   = ModelApplications
        fields  = [
            "external_id",
            "created_by",
            "host",
            "shortname",
            "description",
            "email",
        ]
        
    def validate(self, data):
        data["external_id"] = Alphanumeric(model=ModelUsers).auto_generate()
        return data
    
    def validate_host(self, host):
        if not host:
            raise serializers.ValidationError("Must not be empty")
        
        return host
    
    def validate_shortname(self, shortname):
        if not shortname:
            raise serializers.ValidationError("Must not be empty")
        
        application = ModelApplications.objects.filter(shortname=shortname).exclude(external_id=self.initial.get("external_id")) 
        if application.exists():
            raise serializers.ValidationError("Already exist")
        
        return shortname.lower().strip()
    
    def validate_description(self, description):
        return description.lower().strip() if description or description is not None else description
    
    def validate_email(self, email):
        if not email:
            raise serializers.ValidationError("Must not be empty")
        
        application  = ModelApplications.objects.filter(email=email).exclude(external_id=self.initial.get("external_id"))
        if application.exists():
            raise serializers.ValidationError("Already exist")
        
        return email

class ApplicationSetArchived(serializers.ModelSerializer):
    class Meta:
        model   = ModelApplications
        fields  = [
            "external_id", 
            "is_archived",
            "archived_by",
            "archived_date",
            "archived_note"
        ]
        
    def validate(self, data):
        data["external_id"]     = Alphanumeric(model=ModelUsers).auto_generate()
        data["is_archived"]     = 1
        data["archived_by"]     = self.initial.get("username")
        data["archived_date"]   = datetime.now()
        return data

class ApplicationSecretKey(serializers.ModelSerializer):
    class Meta:
        model   = ModelApplications
        fields  = ["external_id", "secret_key"]
        
    def validate(self, data):
        data["secret_key"]  = Generate(length=15).run()
        return data


# Domains
class Domains(serializers.ModelSerializer):
    class Meta:
        model   = ModelDomains
        fields  = [
            "external_id",
            "created_by",
            "name",
            "url_name",
            "is_archived",
            "archived_date",
            "archived_note",
            "archived_by"
        ]

class DomainRegister(serializers.ModelSerializer):
    class Meta:    
        model   = ModelDomains
        fields  = [
            "external_id",
            "created_by",
            "name",
            "applications",
            "url_name"
        ]
        
    def validate(self, data):
        data["external_id"] = Alphanumeric(model=ModelUsers).auto_generate()
        return data
    
    def validate_name(self, name):
        if not name:
            raise serializers.ValidationError("Must not be empty")
        
        domain  = ModelDomains.objects.filter(name=name)
        if domain.exists():
            raise serializers.ValidationError("Already exist")
        
        return name.lower().strip()
    
    def validate_url_name(self, url_name):
        if not url_name:
            raise serializers.ValidationError("Must not be empty")
        
        domain  = ModelDomains.objects.filter(url_name=url_name)
        if domain.exists():
            raise serializers.ValidationError("URL name already exist")

        return url_name.strip()
