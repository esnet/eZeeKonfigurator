import os
import shutil
import sys

from django import db
from django.core import management
from django.contrib.auth.models import User
from django.contrib.staticfiles import finders
from django.db.models.functions import Lower
from django.shortcuts import render, redirect
from django.http import HttpResponse, JsonResponse
from django.views.decorators.http import require_POST
from django.urls import reverse
import git

from webconfig import models


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
    sensors = models.ClientComponent.objects.filter(client_type="zeek")
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
        return JsonResponse({'success': True, 'num_sensors':
            models.ClientComponent.objects.filter(client_type="zeek", authorized=True).count()})
    elif sensor_type == 'unauthorized':
        return JsonResponse({'success': True, 'num_sensors':
            models.ClientComponent.objects.filter(client_type="zeek", authorized=False).count()})
    elif sensor_type == 'pending':
        return JsonResponse({'success': True, 'num_sensors':
            models.ClientComponent.objects.filter(client_type="zeek", authorized=None).count()})
    elif sensor_type == 'total':
        return JsonResponse({'success': True, 'num_sensors':
            models.ClientComponent.objects.filter(client_type="zeek").count()})
    return JsonResponse({'success': False})


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