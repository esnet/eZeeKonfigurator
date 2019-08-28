import json
import shutil

from django import db
from django.core import management
from django.contrib.auth.models import User
from django.contrib.staticfiles.templatetags.staticfiles import static
from django.http import HttpResponse
from django.shortcuts import render, redirect
from django.views.decorators.csrf import csrf_exempt
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

    return render(request, 'list_sensors.html', {"sensors": sensors})


def _git_client_get_version():
    with open("webconfig/static/ezeekonfigurator_client/refs/heads/master", 'r') as head:
        return head.read()


def _git_copy_server_files():
    """Run 'git update-server-info -f' and copy the resulting files into the static dir"""

    client_repo = git.Repo("./ezeekonfigurator_client/")
    client_repo.git.update_server_info("-f")

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


@csrf_exempt
def client_api(request, ver, sensor_uuid):
    data = json.loads(request.body)
    try:
        s = models.Sensor.objects.get(uuid=sensor_uuid)
    except models.Sensor.DoesNotExist:
        s = models.Sensor.objects.create(uuid=sensor_uuid, hostname=data['hostname'], zeek_version=data['zeek_version'])
    return HttpResponse('')
