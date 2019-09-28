import broker
import datetime
import json
import os
import requests

client_version = "1"

topic = "/ezeekonfigurator/control"

bind_address = os.environ.get("BROKERD_BIND_ADDR", "")
bind_port = os.environ.get("BROKERD_BIND_PORT", None)
ez_url = os.environ.get("URL", "http://localhost:8000/brokerd_api/none") + "/v%s/" % client_version


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
            uuid, options = ev.args()
            for k, v in options.items():
                type_name, value, doc = v
                print(k, v)


if __name__ == "__main__":
    broker_loop()