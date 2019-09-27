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


def django_setup():
    from django.core.wsgi import get_wsgi_application
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'eZeeKonfigurator.settings.development')
    return get_wsgi_application()


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
        print("Error connecting to server")

    endpoint.publish(topic, broker.zeek.Event("eZeeKonfigurator::option_list_request", datetime.datetime.now()))
    while True:
        (t, msg) = subscriber.get()
        ev = broker.zeek.Event(msg)
        if ev.name() == "eZeeKonfigurator::option_list_reply":
            options = ev.args()
            for k, v in options[0][0].items():
                print(k, v)


if __name__ == "__main__":
    application = django_setup()
    broker_loop()