import json
import os
import shutil
import sys

from django import db
from django.core import management
from django.contrib.auth.models import User
from django.contrib.staticfiles import finders
from django.db.models.functions import Lower
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
        management.call_command('collectstatic', verbosity=0, interactive=False)
        return _setup_create_client_pkg(request)

    return list_sensors(request)


def _git_client_get_version():
    path = 'ezeekonfigurator_client/refs/heads/master'
    full_path = finders.find(path)
    if full_path:
        with open(full_path, 'r') as head:
            return head.read()
    else:
        raise FileNotFoundError("Could not determine where static files should live.")


def _git_copy_server_files():
    """Run 'git update-server-info -f' and copy the resulting files into the static dir"""

    for path in sys.path:
        p = os.path.join(path, "ezeekonfigurator_client")
        if os.path.exists(p):
            client_repo = git.Repo(p)
            client_repo.git.update_server_info("-f")
            break

    shutil.copytree(os.path.join(p, ".git"), "webconfig/static/ezeekonfigurator_client")


def _setup_create_client_pkg(request):
    data = {'stage': 2, 'server': request.build_absolute_uri('').strip('/'), 'package_location': '/static/ezeekonfigurator_client'}

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
        #print(v)
        option, opt_created = models.Option.objects.get_or_create(sensor=sensor, namespace=namespace, name=name,
                                                                  datatype=v['type_name'], docstring=v['doc'])
        option.save()

        try:
            setting = models.Setting.objects.get(option=option)
        except models.Setting.DoesNotExist:
            setting = None
        if not setting:
            zeek_val = models.parse_atomic(v['type_name'], v['value'])
            if not zeek_val:
                # Try to parse it as a complex type
                if v['type_name'].startswith('set['):
                    zeek_val = models.ZeekSet.create(v['type_name'], v['value'])
                elif v['type_name'].startswith('vector of '):
                    zeek_val = models.ZeekVector.create(v['type_name'], v['value'])
                else:
                    print("Don't know what to do with", v['type_name'], v['value'])
                    continue

            if zeek_val:
                zeek_val.save()
                setting = models.Setting.objects.create(option=option, value=zeek_val)
                setting.save()

        else:
            # Didn't create it, just update the value.
            setting.value.parse(v['type_name'], v['value'])
            setting.save()

    return HttpResponse('')


def list_sensors(request):
    return render(request, 'list_sensors.html', {"pending_sensors": models.Sensor.objects.filter(authorized=None),
                                                 "unauth_sensors": models.Sensor.objects.filter(authorized=False),
                                                 "auth_sensors": models.Sensor.objects.filter(authorized=True)})


def list_options(request):
    return render(request, 'list_options.html', {"values": models.Setting.objects.filter(option__sensor__authorized=True).order_by(Lower('option__namespace'), Lower('option__name'))})


def export_options(request, ver, sensor_uuid):
    response = render(request, 'export_options.html', {
        "values": models.Setting.objects.filter(option__sensor__authorized=True, option__sensor__uuid=sensor_uuid).order_by('option__namespace',
                                                                                                                            'option__name')},
                  content_type='text/plain')
    response['Content-Disposition'] = 'attachment; filename="ezeekonfigurator.tsv"'
    return response


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


# Below here is for development

def reset(request):
    models.Sensor.objects.all().delete()
    models.Option.objects.all().delete()
    return HttpResponse("OK")