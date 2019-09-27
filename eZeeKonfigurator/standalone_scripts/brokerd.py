import broker
import datetime
import os

topic = "/ezeekonfigurator/control"


def django_setup():
    from django.core.wsgi import get_wsgi_application
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'eZeeKonfigurator.settings.development')
    return get_wsgi_application()


def broker_loop():
    endpoint = broker.Endpoint()
    subscriber = endpoint.make_subscriber(topic)

    print("Broker server started on TCP", endpoint.listen("", 47750))

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