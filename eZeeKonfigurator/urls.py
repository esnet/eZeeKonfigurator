"""eZeeKonfigurator URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/2.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path

import webconfig.views.webui as webui
import webconfig.views.brokerd_api as brokerd_api

urlpatterns = [
    path('', webui.home, name='home'),
    path('activity', webui.changes, name='changes'),
    path('sensors/auth', webui.list_sensors, name='list_sensors'),
    path('sensors/settings', webui.list_options, name='list_options'),
    path('sensors/<int:id>/settings', webui.list_options, name='list_options'),
    path('sensors/settings/<slug:namespace>', webui.list_options, name='list_options'),
    path('sensors/edit_option/<int:id>', webui.edit_option, name='edit_option'),
    path('sensors/append_option/<int:id>', webui.append_option, name='append_option'),

    path('sensors/edit_value/<slug:val_type>/<int:id>', webui.edit_value, name='edit_value'),
    path('sensors/append_value/<slug:val_type>/<int:id>', webui.append_value, name='append_value'),

    path('brokerd_api/v<int:ver>/sensor_info/', brokerd_api.sensor_info, name='sensor_info'),
    path('brokerd_api/v<int:ver>/sensor_option/', brokerd_api.sensor_option, name='sensor_option'),
    path('brokerd_api/v<int:ver>/sensor_hb/', brokerd_api.sensor_heartbeat, name='sensor_heartbeat'),
    path('brokerd_api/v<int:ver>/sensor_last_gasp/', brokerd_api.sensor_last_gasp, name='sensor_last_gasp'),

    path('web_api/sensor/count/<slug:sensor_type>/', webui.get_sensor_count, name='api_sensor_count'),

    path('web_api/sensor/authorize/<int:sensor_id>/', webui.authorize_sensor, name='authorize_sensor'),
    path('web_api/sensor/block/<int:sensor_id>/', webui.block_sensor, name='block_sensor'),
    path('admin/', admin.site.urls),
]
