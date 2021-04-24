import datetime
import ipaddress
import json


def get_index_types(type_name):
    if not ('[' in type_name and ']' in type_name):
        return []

    if type_name.startswith('vector of'):
        return []

    type_name = type_name.replace("['", "[")
    type_name = type_name.replace("']", "]")

    # e.g. table[count,port] of table[foo,bar]
    return type_name.split('[')[1].split(']')[0].replace(', ', ',').split(',')


def get_yield_type(type_name):
    if ' of ' not in type_name:
        return None
    return type_name.split(' of ', 1)[1]


def get_record_types(type_name):
    if type_name.startswith('record { '):
        type_name = type_name.split(' { ', 1)[1].rsplit(' }', 1)[0]

    data = []

    while type_name:
        type_name = type_name.lstrip(' ')
        field_name, type_name = type_name.split(':', 1)
        field_type = ""
        depth = 0
        for i in range(len(type_name)):
            if type_name[i] == ';' and depth == 0:
                break
            if type_name[i:].startswith('record { '):
                depth += 1
            elif type_name[i] == '}':
                depth -= 1
            field_type += type_name[i]
        type_name = type_name[i+1:]

        data.append({'field_name': field_name, 'field_type': field_type})

    return data


def to_json(val):
    """Convert broker types to JSON."""
    if val is None:
        return val

    if isinstance(val, bool) or isinstance(val, str) or isinstance(val, float) or isinstance(val, int) or isinstance(val, bytes):
        return val

    elif isinstance(val, datetime.timedelta):
        return float(val.total_seconds())
    elif isinstance(val, datetime.datetime):
        return float(val.timestamp())

    elif isinstance(val, ipaddress.IPv4Address) or isinstance(val, ipaddress.IPv6Address):
        return val.compressed.lower()
    elif isinstance(val, ipaddress.IPv4Network) or isinstance(val, ipaddress.IPv6Network):
        return val.compressed.lower()

    elif isinstance(val, broker.Count):
        return int(str(val))
    elif isinstance(val, broker.Enum) or isinstance(val, broker.Port):
        return str(val)

    elif isinstance(val, set):
        return [to_json(x) for x in val]
    elif isinstance(val, tuple):
        return [to_json(x) for x in val]
    elif isinstance(val, dict):
        data = {}
        for k, v in val.items():
            tmp_k = to_json(k)
            if isinstance(tmp_k, list):
                tmp_k = json.dumps(tmp_k)
            data[tmp_k] = to_json(v)
        return data
    else:
        raise ValueError("Unknown type", str(type(val)))
