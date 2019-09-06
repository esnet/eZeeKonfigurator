from django.contrib import admin

import webconfig.models


class SensorAdmin(admin.ModelAdmin):
    pass

admin.site.register(webconfig.models.Sensor, SensorAdmin)