import aiohttp
from aiohttp_sse_client import client as sse_client
import asyncio
import broker
import datetime
import ipaddress
import json
import logging
import os
import requests


#logging.basicConfig(level=os.environ.get("LOGLEVEL", "INFO"))
logging.basicConfig(level=os.environ.get("LOGLEVEL", "DEBUG"))
log = logging.getLogger(__name__)

batch_size = 5
client_version = "1"

topic = "/ezeekonfigurator/control"

bind_address = os.environ.get("BROKERD_BIND_ADDR", "")
bind_port = os.environ.get("BROKERD_BIND_PORT", None)
ez_url = os.environ.get("URL", "http://localhost:8000/")
asgi_url = os.environ.get("ASGI_URL", ez_url + "events/")
uuid = os.environ.get("UUID", "not-set")


def to_json(val):
    """Convert broker types to JSON."""
    if val is None:
        return val

    if isinstance(val, bool) or isinstance(val, str) or isinstance(val, float) or isinstance(val, int):
        return val
    elif isinstance(val, bytes):
        return str(val)

    elif isinstance(val, datetime.timedelta):
        return float(val.seconds)
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
        if proto not in ["TCP", "UDP", "ICMP"]:
            proto = "Unknown"

        v = broker.Port(num, proto)

    # Time types
    elif type_name == "interval":
        # Convert to nanoseconds
        s_to_ns = 1000 * 1000 * 1000
        v = broker.Timespan(val * s_to_ns)
    elif type_name == "time":
        v = broker.Timestamp(val)

    else:
        raise NotImplementedError("Converting type", type_name)

    return broker.Data.from_py(v)



def send_to_server(path, data):
    url = ez_url + "brokerd_api/%s/v%s/%s/" % (uuid, client_version, path)
    r = requests.post(url, json=data)
    if r.status_code == 200:
        log.debug("Successfully sent POST to eZeeKonfigurator server")
    else:
        log.warning("Error sending POST to eZeeKonfigurator server: Got %d", r.status_code)


def setup():
    global endpoint, subscriber, port

    endpoint = broker.Endpoint()
    subscriber = endpoint.make_subscriber(topic)

    if not bind_port:
        port = endpoint.listen(bind_address, 0)
    else:
        port = int(bind_port)
        endpoint.listen(bind_address, port)

    log.info("Broker server started on TCP %d", port)


async def broker_loop():
    send_to_server("brokerd_info", {'ip': bind_address, 'port': port})

    endpoint.publish(topic, broker.zeek.Event("eZeeKonfigurator::option_list_request", datetime.datetime.now()))
    while True:
        result = subscriber.get(1, 1)
        if not result:
            await asyncio.sleep(1)
            continue
        else:
            t, msg = result
        log.info("Connected to Zeek server")

        ev = broker.zeek.Event(msg)
        if ev.name() == "eZeeKonfigurator::sensor_info_reply":
            uuid, options = ev.args()
            fqdn, cur_time, net_time, pid, is_live, is_traces, version = options
            log.info("Received sensor_info_reply from", fqdn)

            send_to_server("sensor_info", {'sensor_uuid': uuid, 'zeek_version': version, 'hostname': fqdn})

        elif ev.name() == "eZeeKonfigurator::option_list_reply":
            opt_list = []
            uuid, options = ev.args()
            for option in options:
                for var_name, var_data in option.items():
                    type_name, value, doc = var_data
                    opt_list.append({'name': var_name, 'type': type_name, 'doc': doc, 'val': to_json(value)})
                    if len(opt_list) > batch_size:
                        log.info("Sending %d options to eZeeKonfigurator server" % len(opt_list))
                        send_to_server("sensor_option", {'sensor_uuid': uuid, 'options': opt_list})
                        opt_list = []

            if opt_list:
                send_to_server("sensor_option", {'sensor_uuid': uuid, 'options': opt_list})


async def server_loop():
    while True:
        async with sse_client.EventSource(asgi_url) as event_source:
            try:
                async for event in event_source:
                    if event.type == "stream-open":
                        log.info("Connected to eZeeKonfigurator ASGI")
                    elif event.type == "message" and event.data:
                        data = json.loads(event.data)
                        if data.get('type') == "change":
                            name = data['option']
                            val = from_json(data['val'], data['zeek_type'])
                            endpoint.publish(topic, broker.zeek.Event("eZeeKonfigurator::option_change_request", name, val))
                            log.debug("Received change event from eZeeKonfigurator: %s", data)

            except (ConnectionError, aiohttp.ClientPayloadError, asyncio.TimeoutError):
                pass


async def main():
    setup()

    for f in asyncio.as_completed((server_loop(), broker_loop())):
        result = await f

if __name__ == "__main__":
    asyncio.run(main())
