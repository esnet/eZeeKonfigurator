from django.test import TestCase, Client

from eZeeKonfigurator.utils import *
from webconfig import models

b_uuid = "0d030059-3ec7-42ee-a845-22e5381287ec"
s_uuid = "0d030059-3ec7-42ee-a845-22e5381287ec"


class TestImport(TestCase):
    items = []

    def setUp(self):
        models.BrokerDaemon(uuid=b_uuid, authorized=True).save()
        print(models.BrokerDaemon.objects.all())
        models.Sensor(hostname="localhost", uuid=s_uuid, zeek_version="3.0.0-rc2", authorized=True).save()
        print(models.Sensor.objects.all())
        self.c = Client()

    def test_import(self):
        for s in self.items:
            with self.subTest(val=str(s)):
                response = self.c.post('/brokerd_api/%s/v1/sensor_option/' % b_uuid,
                                       {'sensor_uuid': s_uuid, 'options': [s]}, content_type='application/json')
                self.assertTrue(response.json()['success'])
                self.assertEqual(response.status_code, 200)


class TestProblematic(TestImport):
    items = [
        {'name': "HTTP::http_methods", 'type': "set[string]", 'doc': "Stuff and things", 'val': to_json(set(["MKCOL", "PUT", "CONNECT", "PROPPATCH", "COPY", "TRACE", "LOCK", "POLL", "UNLOCK", "DELETE", "HEAD", "REPORT", "SEARCH", "SUBSCRIBE", "POST", "MOVE", "GET", "BMOVE", "PROPFIND", "OPTIONS"]))}
        ]


class TestFromServer(TestCase):
    def test_set_enum_of_interval(self):
        v = {"Analyzer::ANALYZER_FTP": 360.0, "Analyzer::ANALYZER_SSH": 3600.0}
        from_json(v, "table[enum] of interval")