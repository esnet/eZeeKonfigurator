import broker
import datetime
import ipaddress
import json


def get_index_types(type_name):
    if not ('[' in type_name and ']' in type_name):
        return []

    # e.g. table[count,port] of table[foo,bar]
    return type_name.split('[')[1].split(']')[0].split(', ')


def get_yield_type(type_name):
    if ' of ' not in type_name:
        return None
    return type_name.split(' of ', 1)[1]


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


def from_json(val, type_name):
    """Convert JSON types to broker."""
    if val is None:
        v = val
    # Native types
    elif type_name in ["bool", "int", "double", "string"]:
        v = val

    # Wrapper types
    elif type_name == "count":
        v = broker.Count(val)
    elif type_name == "enum":
        v = broker.Enum(val)

    # Network types
    elif type_name == "addr":
        v = ipaddress.ip_address(val)
    elif type_name == "subnet":
        v = ipaddress.ip_network(val)
    elif type_name == "port":
        num, proto = val.split("/", 1)

        num = int(num)

        proto = proto.upper()
        if proto == "TCP":
            proto = broker.Port.Protocol.TCP
        elif proto == "UDP":
            proto = broker.Port.Protocol.UDP
        elif proto == "ICMP":
            proto = broker.Port.Protocol.ICMP
        else:
            proto = broker.Port.Protocol.Unknown

        v = broker.Port(num, proto)

    # Time types
    elif type_name == "interval":
        v = broker.Timespan(float(val))
    elif type_name == "time":
        v = broker.Timestamp(float(val))

    # Composite types
    elif type_name.startswith("set["):
        inner_type_name = type_name.split('set[', 1)[1]
        inner_type_name = inner_type_name[:-1]
        data = set([from_json(x, inner_type_name) for x in val])
        v = broker.Data(data)

    elif type_name.startswith("vector of "):
        inner_type_name = type_name[10:]
        data = tuple([from_json(x, inner_type_name) for x in val])
        v = broker.Data(data)

    elif type_name.startswith("table["):
        index_types = get_index_types(type_name)
        yield_type = get_yield_type(type_name)

        data = {}

        for k, v in val.items():
            if len(index_types) > 1:
                index = ()
                k = json.loads(k)
                print(k, index_types)
                for i in range(len(index_types)):
                    index = index + tuple([from_json(k[i], index_types[i])])
            else:
                index = from_json(k, index_types[0])

            data[index] = from_json(v, yield_type)

        return broker.Data(data)

    else:
        raise NotImplementedError("Converting type", type_name)

    return v
