import json
import os
import shutil
import sys

from django import db
from django.core import management
from django.contrib.auth.models import User
from django.contrib.staticfiles.templatetags.staticfiles import static
from django.http import HttpResponse, JsonResponse
from django.shortcuts import render, redirect
from django.views.decorators.http import require_POST
from django.views.decorators.csrf import csrf_exempt
from django.urls import reverse
import git

from . import models


def home(request):
    if request.POST:
        return redirect(request.get_full_path())

    # Check if we need to initialize the database
    try:
        users = User.objects.all()
        # Force evaluation of the lazy object
        len(users)
    except db.utils.OperationalError:
        # Run the migrate command first
        management.call_command('migrate')
        users = User.objects.all()

    # If we have no users, add one.

    if not users:
        return _setup_create_user(request)

    # If we have no sensors, help the user to add one.
    sensors = models.Sensor.objects.all()
    if not sensors:
        return _setup_create_client_pkg(request)

    return list_sensors(request)


def _git_client_get_version():
    with open("webconfig/static/ezeekonfigurator_client/refs/heads/master", 'r') as head:
        return head.read()


def _git_copy_server_files():
    """Run 'git update-server-info -f' and copy the resulting files into the static dir"""

    for path in sys.path:
        try:
            client_repo = git.Repo(os.path.join(path, "ezeekonfigurator_client"))
            client_repo.git.update_server_info("-f")
        except git.exc.NoSuchPathError:
            continue

    shutil.copytree("./ezeekonfigurator_client/.git", "webconfig/static/ezeekonfigurator_client")


def _setup_create_client_pkg(request):
    data = {'stage': 2, 'server': request.build_absolute_uri('').strip('/'), 'package_location': static('ezeekonfigurator_client')}

    try:
        data['version'] = _git_client_get_version()
    except FileNotFoundError:
        _git_copy_server_files()

    data['version'] = _git_client_get_version()

    return render(request, 'welcome.html', data)


def _setup_create_user(request):
    password = User.objects.make_random_password()
    User.objects.create_superuser('admin', 'admin@example.com', password)

    return render(request, 'welcome.html', {'stage': 1, 'password': password})


def get_sensor_count(request, sensor_type):
    if sensor_type == 'authorized':
        return JsonResponse({'success': True, 'num_sensors': models.Sensor.objects.filter(authorized=True).count()})
    elif sensor_type == 'unauthorized':
        return JsonResponse({'success': True, 'num_sensors': models.Sensor.objects.filter(authorized=False).count()})
    elif sensor_type == 'pending':
        return JsonResponse({'success': True, 'num_sensors': models.Sensor.objects.filter(authorized=None).count()})
    elif sensor_type == 'total':
        return JsonResponse({'success': True, 'num_sensors': models.Sensor.objects.all().count()})
    return JsonResponse({'success': False})


@csrf_exempt
def client_api_sensor_info(request, ver, sensor_uuid):
    if str(ver) != '1':
        return HttpResponse('Error')

    data = json.loads(request.body)['data']
    try:
        s = models.Sensor.objects.get(uuid=sensor_uuid)
    except models.Sensor.DoesNotExist:
        s = models.Sensor.objects.create(uuid=sensor_uuid, hostname=data['hostname'],
                                         zeek_version=data['zeek_version'], last_ip=request.META.get('REMOTE_ADDR'))

    print("Added sensor", s)
    return HttpResponse('')


@csrf_exempt
def client_api_option_list(request, ver, sensor_uuid):
    if str(ver) != '1':
        return HttpResponse('Error')

    data = json.loads(request.body)['data']
    sensor = models.Sensor.objects.get(uuid=sensor_uuid)
    for k, v in data['options'].items():
        namespace = "GLOBAL"
        if '::' in k:
            namespace, name = k.split('::', 1)
        else:
            name = k

        option, opt_created = models.Option.objects.get_or_create(sensor=sensor, namespace=namespace, name=name,
                                                     datatype=v['type_name'], docstring=v['doc'])
        option.save()
        value, val_created = models.Setting.objects.get_or_create(option=option, value=v['value'])
        value.save()

    return HttpResponse('')


def list_sensors(request):
    return render(request, 'list_sensors.html', {"pending_sensors": models.Sensor.objects.filter(authorized=None),
                                                 "unauth_sensors": models.Sensor.objects.filter(authorized=False),
                                                 "auth_sensors": models.Sensor.objects.filter(authorized=True)})


def list_options(request):
    print(models.Setting.objects.all())
    return render(request, 'list_options.html', {"values": models.Setting.objects.filter(option__sensor__authorized=True).order_by('option__namespace', 'option__name')})



@require_POST
def authorize_sensor(request, sensor_id):
    s = models.Sensor.objects.get(pk=sensor_id)
    s.authorized = True
    s.save()
    return redirect(reverse(list_options))


@require_POST
def block_sensor(request, sensor_id):
    s = models.Sensor.objects.get(pk=sensor_id)
    s.authorized = False
    s.save()
    return list_sensors(request)


### Below here is for development

def reset(request):
    models.Sensor.objects.all().delete()
    return HttpResponse("OK")