from django.contrib import admin

import webconfig.models


class ClientComponentAdmin(admin.ModelAdmin):
    pass

admin.site.register(webconfig.models.ClientComponent, ClientComponentAdmin)