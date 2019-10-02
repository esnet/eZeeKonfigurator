import git
import os
import shutil
import sys
import uuid as uuidlib

from django import db
from django.core import management
from django.contrib.auth.models import User
from django.contrib.staticfiles import finders
from django.db.models.functions import Lower
from django.shortcuts import get_object_or_404, render, redirect
from django.http import HttpResponse, JsonResponse
from django.views.decorators.http import require_POST
from django.views.generic.edit import CreateView, DeleteView, UpdateView
from django.urls import reverse

from django_eventstream import send_event

from webconfig import models
from webconfig import forms


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

    # If we have no brokerd, add one.
    if not models.BrokerDaemon.objects.filter(authorized=True, port__isnull=False):
        return _setup_create_brokerd(request)

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
    data = {'server': request.build_absolute_uri('').strip('/'), 'package_location': '/static/ezeekonfigurator_client'}

    try:
        data['version'] = _git_client_get_version()
    except FileNotFoundError:
        _git_copy_server_files()

    data['version'] = _git_client_get_version()

    return render(request, 'setup_3.html', data)


def _setup_create_user(request):
    password = User.objects.make_random_password()
    User.objects.create_superuser('admin', 'admin@example.com', password)

    return render(request, 'setup_1.html', {'password': password})


def _setup_create_brokerd(request):
    uuid = str(uuidlib.uuid4())
    data = {'server': request.build_absolute_uri('brokerd_api/') + uuid}
    m = models.BrokerDaemon.objects.create(uuid=uuid, authorized=True)
    m.save()

    return render(request, 'setup_2.html', data)


def get_auth(status):
    s = {'authorized': {'authorized': True},
         'unauthorized': {'authorized': False},
         'pending': {'authorized': None},
         }
    return s.get(status, {})


def get_sensor_count(request, sensor_type):
    result = models.Sensor.objects.filter(**get_auth(sensor_type)).count()
    if result:
        return JsonResponse({'success': True, 'num': result})
    else:
        return JsonResponse({'success': False}, status=404)


def get_brokerd_count(request, brokerd_type):
    result = models.BrokerDaemon.objects.filter(port__isnull=False, **get_auth(brokerd_type)).count()
    if result:
        return JsonResponse({'success': True, 'num': result})
    else:
        return JsonResponse({'success': False}, status=404)


def list_sensors(request):
    return render(request, 'list_sensors.html', {"pending_sensors": models.Sensor.objects.filter(authorized=None),
                                                 "unauth_sensors": models.Sensor.objects.filter(authorized=False),
                                                 "auth_sensors": models.Sensor.objects.filter(authorized=True)})


def list_brokerd(request):
    return render(request, 'list_brokerd.html', {"pending_brokers": models.BrokerDaemon.objects.filter(authorized=None),
                                                 "unauth_brokers": models.BrokerDaemon.objects.filter(authorized=False),
                                                 "auth_brokers": models.BrokerDaemon.objects.filter(authorized=True)})


def list_options(request):
    return render(request, 'list_options.html', {"values": models.Setting.objects.filter(option__sensor__authorized=True).order_by(Lower('option__namespace'), Lower('option__name'))})


def edit_set(request, data, obj):
    data['type'] = "set"
    vals = []
    index_elems = models.ZeekTableIndexElement.objects.filter(content_type__model="zeek%s" % obj.type_name,
                                                              object_id=obj.pk).order_by('index_pos')
    for index_elem in index_elems:
        index_elem_model = index_elem.index_elem_ctype.model_class()
        vals += index_elem_model.objects.filter(content_type__model="zeektableindexelement", object_id=index_elem.pk)

    data['vals'] = [(v, forms.get_form_for_model(v)) for v in vals]
    return render(request, 'edit_option_composite.html', data)


def edit_table(request, data, obj):
    data['type'] = "table"
    data['vals'] = []
    for table_val in models.ZeekTableVal.objects.filter(content_type__model="zeek%s" % obj.type_name, object_id=obj.pk):
        idx_vals = [(i.v, forms.get_form_for_model(i.v)) for i in table_val.get_index_vals()]
        table_val = (table_val.v, forms.get_form_for_model(table_val.v))
        data['vals'].append((idx_vals, table_val))

    return render(request, 'edit_option_table.html', data)


def edit_option(request, id):
    s = get_object_or_404(models.Setting, option__sensor__authorized=True, pk=id)

    data = {"setting": s, "type": models.get_name_of_model(s.value)}
    if isinstance(s.value, models.ZeekSet):
        return edit_set(request, data, s.value)
    elif isinstance(s.value, models.ZeekTable):
        return edit_table(request, data, s.value)
    else:
        form = forms.get_form_for_model(s.value, request.POST)
        if request.POST:
            old = str(s.value)
            form.save()
            new = str(s.value)
            if s.option.namespace:
                name = "%s::%s" % (s.option.namespace, s.option.name)
            else:
                name = s.option.name
            send_event('test', 'message', {'type': 'change', 'option': name, 'val': s.value.json(), 'zeek_type': data['type']})
            data['success'] = ["Changes saved: %s -> %s" % (old, new)]
        data['form'] = forms.get_form_for_model(s.value)
        return render(request, 'edit_option_atomic.html', data)


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
    models.BrokerDaemon.objects.all().delete()
    models.Option.objects.all().delete()
    return JsonResponse("OK")