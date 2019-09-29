import broker
import datetime
import ipaddress
import json
import os
import requests

client_version = "1"

topic = "/ezeekonfigurator/control"

bind_address = os.environ.get("BROKERD_BIND_ADDR", "")
bind_port = os.environ.get("BROKERD_BIND_PORT", None)
ez_url = os.environ.get("URL", "http://localhost:8000/brokerd_api/none") + "/v%s/" % client_version


def to_json(val):
    """Convert broker types to JSON"""
    if isinstance(val, bool) or isinstance(val, str) or isinstance(val, float) or isinstance(val, int):
        return json.dumps(val)

    elif isinstance(val, datetime.timedelta):
        return json.dumps(float(val.seconds))
    elif isinstance(val, datetime.datetime):
        return json.dumps(float(val.timestamp()))

    elif isinstance(val, ipaddress.IPv4Address) or isinstance(val, ipaddress.IPv6Address):
        return json.dumps(val.compressed.lower())
    elif isinstance(val, ipaddress.IPv4Network) or isinstance(val, ipaddress.IPv6Network):
        return json.dumps(val.compressed.lower())

    elif isinstance(val, broker.Count):
        return json.dumps(int(str(val)))
    elif isinstance(val, broker.Enum) or isinstance(val, broker.Port):
        return json.dumps(str(val))

    elif isinstance(val, set) or isinstance(val, tuple):
        return json.dumps([to_json(x) for x in val])
    elif isinstance(val, dict):
        return json.dumps({str(to_json(k)): to_json(v) for k, v in val.items()})
    else:
        return "Unknown type", str(type(val))



def broker_loop():
    endpoint = broker.Endpoint()
    subscriber = endpoint.make_subscriber(topic)

    if not bind_port:
        port = endpoint.listen(bind_address, 0)
    else:
        port = int(bind_port)
        endpoint.listen(bind_address, port)

    print("Broker server started on TCP", port)

    r = requests.post(ez_url + "brokerd_info/", json={'ip': bind_address, 'port': port})
    if r.status_code == 200:
        print("Connected to eZeeKonfigurator server")
    else:
        print("Error connecting to server", r.json())

    endpoint.publish(topic, broker.zeek.Event("eZeeKonfigurator::option_list_request", datetime.datetime.now()))
    while True:
        (t, msg) = subscriber.get()
        ev = broker.zeek.Event(msg)
        if ev.name() == "eZeeKonfigurator::sensor_info_reply":
            uuid, options = ev.args()
            fqdn, cur_time, net_time, pid, is_live, is_traces, version = options
            r = requests.post(ez_url + "sensor_info/", json={'sensor_uuid': uuid, 'zeek_version': version, 'hostname': fqdn})
            if r.status_code == 200:
                print("Connected to eZeeKonfigurator server")
            else:
                print("Error connecting to server", r.json())

        elif ev.name() == "eZeeKonfigurator::option_list_reply":
            opt_list = []
            uuid, options = ev.args()
            for option in options:
                for var_name, var_data in option.items():
                    type_name, value, doc = var_data
                    opt_list.append({'name': var_name, 'type': type_name, 'doc': doc, 'val': to_json(value)})

            r = requests.post(ez_url + "sensor_option/", json={'sensor_uuid': uuid, 'options': opt_list})
            if r.status_code == 200:
                print("Sent options to eZeeKonfigurator server")
            else:
                print("Error sending options to server")


if __name__ == "__main__":
    broker_loop()