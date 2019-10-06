import json
from django.views.decorators.http import require_POST
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse

from webconfig import models

api_version = 1

def error(text, status=400):
    return JsonResponse({'success': False, 'errors': [text]}, status=status)


def authorized_brokerd(view_func):
    def wrapper(*args, **kw):
        try:
            uuid = kw['brokerd_uuid']
            models.BrokerDaemon.objects.get(uuid=uuid, authorized=True)
        except:
            return error('unauthorized_brokerd', 404)

        return view_func(*args, **kw)
    return wrapper


def authorized_sensor(view_func):
    def wrapper(*args, **kw):
        try:
            uuid = kw['sensor_uuid']
            models.Sensor.objects.get(uuid=uuid, authorized=True)
        except:
            return error('unauthorized_sensor', 404)

        return view_func(*args, **kw)
    return wrapper


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
@authorized_brokerd
def sensor_info(request, ver, brokerd_uuid):
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
@authorized_brokerd
def sensor_option(request, ver, brokerd_uuid):
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
@authorized_brokerd
def brokerd_info(request, ver, brokerd_uuid):
    """Update the ip:port broker is listening on"""
    try:
        data = json.loads(request.body)
    except:
        return error('json_parsing_error')

    # This should exist from @authorized_brokerd
    m = models.BrokerDaemon.objects.get(uuid=brokerd_uuid)

    try:
        ip = data["ip"]
        if not ip:
            ip = request.META.get('REMOTE_ADDR')
        m.ip = ip
        m.port = data["port"]
    except KeyError:
        return error('missing_fields')

    try:
        m.save()
    except:
        return error('brokerd_model_save', 500)

    return JsonResponse({'success': True})

#
#
# @csrf_exempt
# def client_api_option_list(request, ver, sensor_uuid):
#     if str(ver) != '1':
#         return HttpResponse('Error')
#
#     data = json.loads(request.body)['data']
#     sensor = models.Sensor.objects.get(uuid=sensor_uuid)
#     for k, v in data['options'].items():
#         namespace = "GLOBAL"
#         if '::' in k:
#             namespace, name = k.split('::', 1)
#         else:
#             name = k
#         #print(v)
#         option, opt_created = models.Option.objects.get_or_create(sensor=sensor, namespace=namespace, name=name,
#                                                                   datatype=v['type_name'], docstring=v['doc'])
#         option.save()
#
#         try:
#             setting = models.Setting.objects.get(option=option)
#         except models.Setting.DoesNotExist:
#             setting = None
#         if not setting:
#             zeek_val = models.parse_atomic(v['type_name'], v['value'])
#             if not zeek_val:
#                 # Try to parse it as a complex type
#                 if v['type_name'].startswith('set['):
#                     zeek_val = models.ZeekSet.create(v['type_name'], v['value'])
#                 elif v['type_name'].startswith('vector of '):
#                     zeek_val = models.ZeekVector.create(v['type_name'], v['value'])
#                 else:
#                     print("Don't know what to do with", v['type_name'], v['value'])
#                     continue
#
#             if zeek_val:
#                 zeek_val.save()
#                 setting = models.Setting.objects.create(option=option, value=zeek_val)
#                 setting.save()
#
#         else:
#             # Didn't create it, just update the value.
#             setting.value.parse(v['type_name'], v['value'])
#             setting.save()
#
#     return HttpResponse('')
