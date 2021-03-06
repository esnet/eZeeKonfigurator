import json
from django.http import JsonResponse
from django.shortcuts import get_object_or_404
from django.views.decorators.http import require_POST
from django.views.decorators.csrf import csrf_exempt

from webconfig import models

api_version = 1


def error(text, status=400):
    return JsonResponse({'success': False, 'errors': [text]}, status=status)


# def authorized_sensor(view_func):
#     def wrapper(*args, **kw):
#         try:
#             uuid = kw['sensor_uuid']
#             models.Sensor.objects.get(uuid=uuid, authorized=True)
#         except:
#             return error('unauthorized_sensor', 404)
#
#         return view_func(*args, **kw)
#     return wrapper


def check_version(view_func):
    def wrapper(*args, **kw):
        try:
            version = kw['ver']
            if version != api_version:
                raise ValueError
        except:
            return error('version_mismatch', 426)

        return view_func(*args, **kw)
    return wrapper


@csrf_exempt
@require_POST
@check_version
def sensor_info(request, ver):
    """Update or create a Zeek sensor"""
    try:
        data = json.loads(request.body)
    except:
        return error('json_parsing_error')

    try:
        s, created = models.Sensor.objects.get_or_create(uuid=data['sensor_uuid'])
        s.zeek_version = data['zeek_version']
        s.hostname = data['hostname']
    except KeyError:
        return error('missing_fields')

    try:
        s.save()
    except:
        return error('sensor_model_create_or_get', 500)

    return JsonResponse({'success': True, 'created': created})


@csrf_exempt
@require_POST
@check_version
def sensor_option(request, ver):
    """Update or create a Zeek sensor option"""
    try:
        data = json.loads(request.body)
    except:
        return error('json_parsing_error')

    try:
        s = models.Sensor.objects.get(uuid=data['sensor_uuid'])
        options = data['options']
    except KeyError:
        return error('missing_fields')
    except models.Sensor.DoesNotExist:
        return error('sensor_not_found', 404)

    successes = 0

    for opt in options:
        name = opt['name']
        namespace = None
        if '::' in name:
            namespace, name = name.split('::', 1)
        o, created = models.Option.objects.get_or_create(namespace=namespace, name=name, sensor=s)

        o.datatype = opt['type']
        if opt['doc']:
            o.docstring = opt['doc']
        o.save()

        try:
            setting = models.Setting.objects.get(option=o)
            existing_vals = models.ZeekVal.filter(opt['type'], opt['val']).filter(settings=setting)
            if len(existing_vals) == 1:
                # We have a value that already matches
                continue
            elif len(existing_vals) == 0:
                # We need to update the value
                v = models.ZeekVal.create(opt['type'], opt['val'])
                setting.value = v
                setting.save()
        except models.Setting.DoesNotExist:
            v = models.ZeekVal.create(opt['type'], opt['val'])
            setting = models.Setting.objects.create(option=o, value=v)
            setting.save()

        if setting:
            successes += 1

    return JsonResponse({'success': successes == len(options)})

@csrf_exempt
@require_POST
@check_version
def sensor_heartbeat(request, ver):
    """Update last seen time on a Zeek sensor"""
    try:
        data = json.loads(request.body)
    except:
        return error('json_parsing_error')

    s = get_object_or_404(models.Sensor, uuid=data['sensor_uuid'])
    s.save()

    return JsonResponse({'success': True})


@csrf_exempt
@require_POST
@check_version
def sensor_last_gasp(request, ver):
    """Update last seen time on a Zeek sensor"""
    try:
        data = json.loads(request.body)
    except:
        return error('json_parsing_error')

    s = get_object_or_404(models.Sensor, uuid=data['sensor_uuid'])
    s.save()

    return JsonResponse({'success': True})