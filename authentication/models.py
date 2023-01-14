from django.db import models

class Token(models.Model):
    external_id     = models.IntegerField(blank=True, null=False)
    created         = models.DateTimeField(auto_now_add=True)
    created_by      = models.CharField(max_length=100, blank=True, null=True)
    token           = models.CharField(max_length=155, blank=True, null=False)
    credential      = models.JSONField(blank=True, null=False)
    expired_date    = models.DateTimeField(blank=True, null=True)
    is_archived     = models.BooleanField(default=False)
    archived_date   = models.DateTimeField(blank=True, null=True)
    archived_note   = models.TextField(blank=True, null=True)
    archived_by     = models.CharField(max_length=100, blank=True, null=True)
    
    def __str__(self):
        return "{}".format(self.external_id)
