from django.db import models


class Sensor(models.Model):
    """Zeek sensor"""
    hostname = models.CharField(max_length=150)
    uuid = models.UUIDField()
    zeek_version = models.CharField(max_length=30)
    first_seen = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField(auto_now=True)

    def __str__(self):
        return "%s (%s)" % (self.hostname, self.zeek_version)