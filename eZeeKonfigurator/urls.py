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
    path('sensors/auth', webui.list_sensors, name='list_sensors'),
    path('sensors/settings', webui.list_options, name='list_options'),
    path('sensors/edit_option/<int:id>', webui.edit_option, name='edit_option'),

    #path('client_api/v<int:ver>/<slug:sensor_uuid>/option_list/', webconfig.views.client_api_option_list, name='option_list'),
    path('brokerd_api/<slug:brokerd_uuid>/v<int:ver>/sensor_info/', brokerd_api.sensor_info, name='sensor_info'),
    path('brokerd_api/<slug:brokerd_uuid>/v<int:ver>/sensor_option/', brokerd_api.sensor_option, name='sensor_option'),
    path('brokerd_api/<slug:brokerd_uuid>/v<int:ver>/brokerd_info/', brokerd_api.brokerd_info, name='brokerd_info'),
    path('client_api/v<int:ver>/<slug:sensor_uuid>/export_options/', webui.export_options, name='export_options'),

    path('web_api/sensor/count/<slug:sensor_type>/', webui.get_sensor_count, name='api_sensor_count'),
    path('web_api/brokerd/count/<slug:brokerd_type>/', webui.get_brokerd_count, name='api_brokerd_count'),

    path('web_api/sensor/authorize/<int:sensor_id>/', webui.authorize_sensor, name='authorize_sensor'),
    path('web_api/sensor/block/<int:sensor_id>/', webui.block_sensor, name='block_sensor'),
    path('admin/', admin.site.urls),

    path('dev/reset/', webui.reset),
]
