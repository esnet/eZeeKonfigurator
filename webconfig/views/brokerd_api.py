import json
from django.views.decorators.http import require_POST
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse

from webconfig import models


def error(text):
    return JsonResponse({'success': False, 'errors': [text]})


def authorized_brokerd(view_func):
    def wrapper(*args, **kw):
        try:
            uuid = kw['brokerd_uuid']
            models.ClientComponent.objects.get(client_type="brokerd", uuid=uuid, authorized=True)
        except:
            return error('unauthorized_brokerd')

        return view_func(*args, **kw)
    return wrapper


def authorized_sensor(view_func):
    def wrapper(*args, **kw):
        try:
            uuid = kw['sensor_uuid']
            models.ClientComponent.objects.get(client_type="zeek", uuid=uuid, authorized=True)
        except:
            return error('unauthorized_sensor')

        return view_func(*args, **kw)
    return wrapper


def check_version(view_func):
    def wrapper(*args, **kw):
        try:
            version = kw['ver']
            if version != '1':
                raise ValueError
        except:
            return error('version_mismatch')

        return view_func(*args, **kw)
    return wrapper


@require_POST
@check_version
@authorized_brokerd
@csrf_exempt
def sensor_info(request, ver, brokerd_uuid):
    try:
        data = json.loads(request.body)
    except:
        return error('json_parsing_error')

    try:
        params = {
                'sensor_uuid': data['sensor_uuid'],
                'client_type': "zeek",
                'client_version': data["client_version"],
                'hostname': data["hostname"],
        }
    except KeyError:
        return error('missing_fields')

    try:
        s, created = models.ClientComponent.objects.get_or_create(**params)
    except:
        return error('sensor_model_create_or_get')

    return JsonResponse({'success': True, 'created': created})

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
