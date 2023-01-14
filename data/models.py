from django.db import models

class Applications(models.Model):
    external_id     = models.IntegerField(blank=True, null=False)
    created         = models.DateTimeField(auto_now_add=True)
    created_by      = models.CharField(max_length=100, blank=True, null=True)
    host            = models.URLField(blank=True, null=False)
    shortname       = models.CharField(max_length=45, blank=True, null=False)
    description     = models.CharField(max_length=100, blank=True, null=False)
    email           = models.EmailField(max_length=100, blank=True, null=False)
    secret_key      = models.CharField(max_length=255, blank=True, null=False)
    is_archived     = models.BooleanField(default=False)
    archived_date   = models.DateTimeField(blank=True, null=True)
    archived_note   = models.TextField(blank=True, null=True)
    archived_by     = models.CharField(max_length=100, blank=True, null=True)
        
    def __str__(self):
        return "{}".format(self.shortname)

class Roles(models.Model):
    external_id = models.IntegerField(blank=True, null=False)
    created     = models.DateTimeField(auto_now_add=True)
    created_by  = models.CharField(max_length=100, blank=True, null=True)
    name        = models.CharField(max_length=45, blank=True, null=False)
    application = models.ForeignKey(Applications, on_delete=models.PROTECT, blank=True, null=False)

    def __str__(self):
        return "{}".format(self.name)
    
class Domains(models.Model):
    external_id     = models.IntegerField(blank=True, null=False)
    created         = models.DateTimeField(auto_now_add=True)
    created_by      = models.CharField(max_length=100, blank=True, null=True)
    name            = models.CharField(max_length=45, blank=True, null=False)
    applications    = models.ManyToManyField(Applications, blank=True)
    url_name        = models.CharField(max_length=45, blank=True, null=True)
    information     = models.JSONField(blank=True, null=True)
    description     = models.CharField(max_length=255, blank=True, null=True)
    is_archived     = models.BooleanField(default=False)
    archived_date   = models.DateTimeField(blank=True, null=True)
    archived_note   = models.TextField(blank=True, null=True)
    archived_by     = models.CharField(max_length=100, blank=True, null=True)
    
    def __str__(self):
        return "{}".format(self.external_id)

class Users(models.Model):
    external_id     = models.IntegerField(blank=True, null=False)
    created         = models.DateTimeField(auto_now_add=True)
    created_by      = models.CharField(max_length=100, blank=True, null=True)
    roles           = models.ManyToManyField(Roles, blank=True)
    applications    = models.ManyToManyField(Applications, blank=True)
    domains         = models.ManyToManyField(Domains, blank=True)
    id_card_type    = models.CharField(max_length=10, blank=True, null=True)
    id_card_number  = models.CharField(max_length=45, blank=True, null=True)
    username        = models.CharField(max_length=45, blank=True, null=True)
    firstname       = models.CharField(max_length=45, blank=True, null=True)
    lastname        = models.CharField(max_length=45, blank=True, null=True)
    place_of_birth  = models.CharField(max_length=100, blank=True)
    birthdate       = models.DateField(blank=False, null=True, default=None)
    status          = models.CharField(max_length=20, blank=True, null=True)
    gender          = models.CharField(max_length=20, blank=False, null=True)
    religion        = models.CharField(max_length=20, blank=False, null=True)
    email           = models.EmailField(max_length=100, blank=True, null=False)
    address         = models.CharField(max_length=100, blank=True, null=True)
    district        = models.CharField(max_length=45, blank=True, null=True)
    sub_district    = models.CharField(max_length=45, blank=True, null=True)
    phone_number    = models.CharField(max_length=20, blank=True, null=False)
    secret_key      = models.CharField(max_length=255, blank=True, null=False)
    last_login      = models.DateTimeField(blank=True, null=True)
    is_archived     = models.BooleanField(default=False)
    archived_date   = models.DateTimeField(blank=True, null=True)
    archived_note   = models.TextField(blank=True, null=True)
    archived_by     = models.CharField(max_length=100, blank=True, null=True)
    is_logged_in    = models.BooleanField(default=False)
    fcm_name        = models.TextField(blank=True, null=True)

    def __str__(self):
        return '{}'.format(self.email)