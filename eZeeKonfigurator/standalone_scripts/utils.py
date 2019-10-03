import broker
import datetime
import ipaddress


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

    elif isinstance(val, set) or isinstance(val, tuple):
        return [to_json(x) for x in val]
    elif isinstance(val, dict):
        return {str(to_json(k)): to_json(v) for k, v in val.items()}
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
        num = val.get('port')

        proto = val.get("proto").upper()
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
        v = broker.Timespan(val * 1.0)
    elif type_name == "time":
        v = broker.Timestamp(val)

    else:
        raise NotImplementedError("Converting type", type_name)

    return v
