from django.db import models


class Sensor(models.Model):
    """Zeek sensor"""
    hostname = models.CharField(max_length=150)
    uuid = models.UUIDField()
    zeek_version = models.CharField(max_length=30)

    first_seen = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField(auto_now=True)
    last_ip = models.GenericIPAddressField()

    authorized = models.BooleanField(blank=True, null=True)

    def __str__(self):
        return "%s (%s)" % (self.hostname, self.zeek_version)


class Option(models.Model):
    namespace = models.CharField(max_length=100, default="GLOBAL")
    name = models.CharField(max_length=100)
    datatype = models.CharField(max_length=100)
    docstring = models.CharField(max_length=1000)
    sensor = models.ForeignKey('Sensor', on_delete=models.CASCADE)


class Setting(models.Model):
    option = models.ForeignKey('Option', on_delete=models.CASCADE)
    value = models.CharField(max_length=1000)