from django.contrib import admin

import webconfig.models


class DefaultAdmin(admin.ModelAdmin):
    pass


admin.site.register(webconfig.models.Sensor, DefaultAdmin)