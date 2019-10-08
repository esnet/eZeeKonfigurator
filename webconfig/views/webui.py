import git
import os
import shutil
import sys
import uuid as uuidlib

from django import db
from django.core import management
from django.conf import settings
from django.contrib.auth.models import User
from django.db.models.functions import Lower
from django.shortcuts import get_object_or_404, render, redirect
from django.http import HttpResponse, JsonResponse
from django.views.decorators.http import require_POST
from django.urls import reverse

from django_eventstream import send_event

from webconfig import models
from webconfig import forms
from eZeeKonfigurator import utils


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
    auth = not getattr(settings, "BROKERD_AUTH_ENABLED", False)
    if not models.BrokerDaemon.objects.filter(authorized=auth, port__isnull=False):
        return _setup_create_brokerd(request)

    # If we have no sensors, help the user to add one.
    sensors = models.Sensor.objects.all()
    if not sensors:
        management.call_command('collectstatic', verbosity=0, interactive=False)
        return render(request, 'setup_3.html')

    return list_sensors(request)


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


def list_options(request, namespace=None):
    settings = models.Setting.objects.filter(option__sensor__authorized=True)
    if namespace:
        settings = settings.filter(option__namespace=namespace)
    settings = settings.order_by(Lower('option__namespace'), Lower('option__name'))
    return render(request, 'list_options.html', {"values": settings})


def update_val(form, instance):
    old = str(instance)
    if not form.is_valid():
        return False, str(form)

    form.save()
    new = str(instance)

    if old == new:
        result = ""
    else:
        result = "%s -> %s" % (old, new)

    return True, result


def get_container_items_pattern(obj, request, handle_post=True):
    items = []

    # Empty request.POST causes this to not validate
    data = None
    if request.POST and handle_post:
        data = request.POST

    for item in obj.items.all().order_by('position'):
        # Each item is an element in our container.
        keys = [{'obj': k, 'form': forms.get_form_for_model(k.v, data)} for k in item.keys.all()]
        if item.v:
            items.append({'obj': item, 'form': forms.get_form_for_model(item.v, data), 'keys': keys, 'id': str(item.id)})
        else:
            items.append({'keys': keys, 'id': str(item.id)})

    return items


def get_container_items_table(obj, request, handle_post=True):
    items = []

    # Empty request.POST causes this to not validate
    data = None
    if request.POST and handle_post:
        data = request.POST

    for item in obj.items.all().order_by('position'):
        # Each item is an element in our container.
        keys = [{'obj': k, 'form': forms.get_form_for_model(k.v, data)} for k in item.keys.all()]
        if item.v:
            try:
                items.append({'obj': item, 'form': forms.get_form_for_model(item.v, data), 'keys': keys})
            except ValueError:
                # Our value is a composite type.
                t = ""

                if isinstance(item.v, models.ZeekPattern):
                    t = "pattern"

                result = {'keys': keys, 'id': str(item.id), 'readonly': str(item)}
                if t:
                    result['edit_link'] = reverse('edit_value', kwargs={'id': item.v.id, 'val_type': t})

                items.append(result)
        else:
            items.append({'keys': keys, 'id': str(item.id)})

    return items


def get_container_items_record(obj, request, handle_post=True):
    items = []

    # Empty request.POST causes this to not validate
    data = None
    if request.POST and handle_post:
        data = request.POST

    for item in obj.fields.all().order_by('index_pos'):
        try:
            if item.val:
                items.append(
                    {'obj': item, 'form': forms.get_form_for_model(item.val, data)})
        except ValueError:
            # Composite type
            if isinstance(item, models.ZeekRecord) or item is models.ZeekRecord:
                readonly = str(item)
            elif isinstance(item, models.ZeekRecordField) or item is models.ZeekRecordField:
                readonly = str(item)
            else:
                readonly = str(item.v)
            items.append({'id': str(item.id), 'readonly': readonly})

    return items


def get_container_items(obj, request, handle_post=True):
    if isinstance(obj, models.ZeekPattern):
        return get_container_items_pattern(obj, request, handle_post)

    if isinstance(obj, models.ZeekContainer):
        return get_container_items_table(obj, request, handle_post)

    if isinstance(obj, models.ZeekRecord):
        return get_container_items_record(obj, request, handle_post)


def get_empty(request, obj, handle_post=True):
    data = None
    if request.POST and handle_post:
        data = request.POST

    keys = []
    idx_types = utils.get_index_types(obj.index_types)
    for i in range(len(idx_types)):
        if idx_types[i]:
            keys.append({'form': forms.get_empty_form(models.get_model_for_type(idx_types[i]), data, prefix=str(i))})

    f = []
    record_fields = []

    if obj.yield_type:
        try:
            f.append(forms.get_empty_form(models.get_model_for_type(obj.yield_type), data))
        except ValueError:
            if obj.yield_type.startswith('record'):
                for t in utils.get_record_types(obj.yield_type):
                    #
                    # idx_types = utils.get_index_types(t['field_type'])
                    # if not idx_types:
                    #     raise NotImplementedError("Don't know how to handle this record with no index types")
                    # if len(idx_types) > 1:
                    #     raise NotImplementedError("Don't know how to handle this record with multiple index types")
                    m = models.get_model_for_type(t['field_type'])

                    record_fields.append({'name': t['field_name'], 'type': t['field_type']})
                    f.append(forms.get_empty_form(m, data, required=False, prefix=t['field_name'], type_name=t['field_type']))
            else:
                for idx in utils.get_index_types(obj.yield_type):
                    f.append(forms.get_empty_form(models.get_model_for_type(idx), data))

    all_valid = data and (keys or f)
    for k in keys:
        if not k['form'].is_valid():
            all_valid = False

    for idx_form in f:
        if not idx_form.is_valid() and not record_fields:
            all_valid = False

    if all_valid and not record_fields:
        ctr_item = None
        for idx_form in f:
            if idx_form.is_valid():
                item_val = idx_form.save()
                ctr_item = models.ZeekContainerItem(parent=obj, v=item_val, position=len(obj.items.all()))
        if not f:
            ctr_item = models.ZeekContainerItem(parent=obj, position=len(obj.items.all()))

        if ctr_item:
            ctr_item.save()

        for i in range(len(keys)):
            key_val = keys[i]['form'].save()
            k = models.ZeekContainerKey(parent=ctr_item, v=key_val, index_offset=i)
            k.save()

        return {'forms': f, 'keys': keys}, str(ctr_item)

    elif all_valid and record_fields:
        record = models.ZeekRecord(field_types=obj.yield_type)
        record.save()

        for i in range(len(f)):
            idx_form = f[i]
            field = record_fields[i]

            if idx_form.is_valid():
                item_val = idx_form.save()
                field_item = models.ZeekRecordField(parent=record, val=item_val, index_pos=i,
                                                    name=field['name'], val_type=field['type'])
                field_item.save()

        ctr_item = models.ZeekContainerItem(parent=obj, position=len(obj.items.all()), v=record)
        ctr_item.save()

        for i in range(len(keys)):
            key_val = keys[i]['form'].save()
            k = models.ZeekContainerKey(parent=ctr_item, v=key_val, index_offset=i)
            k.save()

        return {'forms': f, 'keys': keys}, str(ctr_item)

    return {'forms': f, 'keys': keys, 'record_fields': record_fields}, False


def append_container(request, data, obj):
    if obj.ctr_type != 'v':
        data['idx_types'] = [x.replace("'", "") for x in utils.get_index_types(obj.index_types)]

    data['yield_type'] = obj.yield_type

    data['errors'] = []
    changes = []

    data['empty'], added = get_empty(request, obj)

    if added:
        changes.append("Added: %s" % added)
        change_event = {'type': "change", 'option': data['setting'].option.get_name(), 'val': obj.json(), 'zeek_type': obj.type_name,
                        'uuid': data['setting'].option.sensor.uuid}
        send_event('test', 'message', change_event)

    data['items'] = get_container_items(obj, request, False)

    return render(request, 'edit_option_composite.html', data)


def edit_container(request, data, s):
    obj = s.value

    if obj.ctr_type != 'v':
        data['idx_types'] = [x.replace("'", "") for x in utils.get_index_types(obj.index_types)]
    data['yield_type'] = obj.yield_type

    data['errors'] = []
    changes = []

    old = str(obj)

    if request.POST:
        for item in obj.items.all().order_by('position'):
            for key in item.keys.all():
                f = forms.get_form_for_model(key.v, request.POST)
                valid, msg = update_val(f, key.v)

            if item.v:
                try:
                    f = forms.get_form_for_model(item.v, request.POST)
                    valid, msg = update_val(f, item.v)
                except ValueError:
                    pass

        new = str(obj)
        if old != new:
            changes.append("Updated %s -> %s" % (old, new))

        # Now we delete
        for k, v in request.POST.items():
            if k.startswith('delete_') and v == 'on':
                k = k.replace('delete_', "")
                try:
                    i = obj.items.get(id=k)
                    val = str(i)
                    i.delete()
                    changes.append("Deleted " + val)
                except obj.DoesNotExist:
                    data['errors'].append("Could not find object '%s' to delete." % k)


    data['empty'], added = get_empty(request, obj, False)

    if added:
        changes.append("Added: %s" % added)

    if changes:
        data['success'] = ["Changes saved: " + "\n".join(changes)]
        change_event = {'type': "change", 'option': s.option.get_name(), 'val': obj.json(), 'zeek_type': obj.type_name,
                        'uuid': s.option.sensor.uuid}
        send_event('test', 'message', change_event)

    data['items'] = get_container_items(obj, request)

    return render(request, 'edit_option_composite.html', data)


def edit_option(request, id):
    s = get_object_or_404(models.Setting, option__sensor__authorized=True, pk=id)

    args = {'id': id}
    data = {"setting": s, "type": models.get_doc_types(s.value), "edit_url": reverse('edit_option', kwargs=args),
            "append_url": reverse('append_option', kwargs=args)}

    if isinstance(s.value, models.ZeekContainer):
        return edit_container(request, data, s)
    else:
        data['form'] = forms.get_form_for_model(s.value, request.POST)
        if request.POST:
            old = str(s)
            if not request.POST.get('change_message'):
                print("NOPE")
            if data['form'].is_valid():
                data['form'].save()
            new = str(s)
            name = s.option.get_name()
            if old != new:
                change_event = {'type': "change", 'option': name, 'val': s.value.json(), 'zeek_type': models.get_name_of_model(s.value), 'uuid': s.option.sensor.uuid}
                send_event('test', 'message', change_event)
                data['success'] = ["Changes saved: %s -> %s" % (old, new)]
        else:
            data['form'] = forms.get_form_for_model(s.value)
        return render(request, 'edit_option_atomic.html', data)


def append_option(request, id):
    """Only used for containers."""
    s = get_object_or_404(models.Setting, option__sensor__authorized=True, pk=id)

    args = {'id': id}
    data = {"setting": s, "type": models.get_doc_types(s.value), "edit_url": reverse('edit_option', kwargs=args),
            "append_url": reverse('append_option', kwargs=args)}

    if not isinstance(s.value, models.ZeekContainer):
        return HttpResponse(400, "Can only append to a container.")

    return append_container(request, data, s.value)


def edit_value(request, val_type, id):
    if val_type not in ["table", "pattern", "record"]:
        return HttpResponse(400, "Only supported for composite types")
    data = {}
    if val_type == "table":
        data['val'] = get_object_or_404(models.ZeekContainer, pk=id)
    elif val_type == "pattern":
        data['val'] = get_object_or_404(models.ZeekPattern, pk=id)
    elif val_type == "record":
        data['val'] = get_object_or_404(models.ZeekRecord, pk=id)

    data['child'] = {'datatype': data['val'].type_name }
    data['items'] = get_container_items(data['val'], request)
    data['edit_url'] = reverse('edit_value', kwargs={'id': id, 'val_type': val_type})

    return render(request, 'edit_option_composite_nested.html', data)

def append_value(request, val_type, id):
    return


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