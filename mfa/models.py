from django.db import models
from django.conf import settings
from django.contrib.postgres.fields import JSONField

from jose import jwt


class UserKey(models.Model):
    username = models.CharField(max_length=250)
    properties = JSONField(null=True)
    added_on = models.DateTimeField(auto_now_add=True)
    key_type = models.CharField(max_length=25, default="TOTP")
    enabled = models.BooleanField(default=True)
    expires = models.DateTimeField(null=True, default=None, blank=True)
    last_used = models.DateTimeField(null=True, default=None, blank=True)

    def save(self, *args, **kwargs):
        if self.key_type == "Trusted Device" and self.properties.get("signature", "") == "":
            self.properties["signature"] = jwt.encode({
                "username": self.username,
                "key": self.properties["key"]
            }, settings.SECRET_KEY)
        super().save(*args, **kwargs)

    def __str__(self):
        return "{} -- {}".format(self.username, self.key_type)

    class Meta:
        app_label = 'mfa'
