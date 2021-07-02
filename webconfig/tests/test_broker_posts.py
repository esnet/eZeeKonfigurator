from django.test import TestCase, Client

from broker_json.conversions import from_json, to_json
from webconfig import models

s_uuid = "0d030059-3ec7-42ee-a845-22e5381287ec"


class TestImport(TestCase):
    items = []

    def setUp(self):
        models.Sensor(hostname="localhost", uuid=s_uuid, zeek_version="3.0.0-rc2", authorized=True).save()
        self.c = Client()

    def test_import(self):
        i = 1
        for s in self.items:
            with self.subTest(val=str(s)):
                response = self.c.post('/brokerd_api/v1/sensor_option/',
                                       {'sensor_uuid': s_uuid, 'options': [s]},
                                       content_type='application/json')
                self.assertTrue(response.json()['success'])
                self.assertEqual(response.status_code, 200)
                response = self.c.get('/sensors/edit_option/%d' % i)
                self.assertEqual(response.status_code, 200)
                self.assertIn(s['name'], response.content.decode("utf-8"))
                i += 1


class TestProblematic(TestImport):
    items = [
        {'name': "HTTP::http_methods", 'type': "set[string]", 'doc': "Stuff and things", 'val': to_json(set(["MKCOL", "PUT", "CONNECT", "PROPPATCH", "COPY", "TRACE", "LOCK", "POLL", "UNLOCK", "DELETE", "HEAD", "REPORT", "SEARCH", "SUBSCRIBE", "POST", "MOVE", "GET", "BMOVE", "PROPFIND", "OPTIONS"]))},
        {'name': "FTP::cmd_reply_code", "type": "set[string,count]", 'doc': "FTP status codes",
        'val': [["CDUP", 501], ["APPE", 550], ["STOU", 451], ["STOU", 553], ["CLNT", 200], ["TYPE", 504], ["APPE", 125], ["APPE", 425], ["CWD", 501], ["ALLO", 504], ["DELE", 421], ["DELE", 501], ["HELP", 501], ["EPRT", 500], ["RNTO", 532], ["APPE", 530], ["STOU", 500], ["RMD", 501], ["MKD", 500], ["RNFR", 450], ["ALLO", 200], ["OPTS", 501], ["MLSD", 250], ["OPTS", 200], ["ABOR", 500], ["LIST", 500], ["CDUP", 421], ["RETR", 150], ["STOU", 550], ["REST", 530], ["APPE", 226], ["RNFR", 530], ["STOR", 451], ["STOU", 452], ["PASV", 502], ["RNFR", 500], ["SYST", 501], ["ALLO", 501], ["NLST", 421], ["LIST", 550], ["STOR", 426], ["LIST", 125], ["STOU", 226], ["MLST", 226], ["RETR", 500], ["USER", 530], ["STOU", 532], ["STOR", 110], ["ACCT", 503], ["MLSD", 226], ["PWD", 502], ["RNFR", 550], ["STOU", 530], ["NLST", 451], ["STOR", 226], ["LPRT", 500], ["CDUP", 500], ["LIST", 421], ["PASS", 503], ["ALLO", 202], ["STOR", 425], ["MDTM", 550], ["STOU", 426], ["DELE", 500], ["STRU", 501], ["MODE", 504], ["NLST", 226], ["SYST", 530], ["PWD", 257], ["MLSD", 150], ["SMNT", 530], ["APPE", 450], ["APPE", 502], ["CWD", 530], ["HELP", 421], ["RNTO", 553], ["NLST", 502], ["STOR", 150], ["FEAT", 502], ["OPTS", 451], ["MLSD", 500], ["EPRT", 501], ["MODE", 421], ["NLST", 426], ["TYPE", 501], ["RETR", 125], ["LIST", 451], ["REST", 502], ["STOU", 421], ["CWD", 550], ["NOOP", 200], ["SITE", 501], ["FEAT", 500], ["SIZE", 550], ["USER", 230], ["SYST", 502], ["STOU", 450], ["ACCT", 202], ["PASS", 202], ["RETR", 425], ["NLST", 500], ["CWD", 502], ["HELP", 500], ["PASV", 500], ["<init>", 0], ["MLST", 250], ["RNTO", 250], ["EPRT", 200], ["STOU", 125], ["TYPE", 500], ["RMD", 502], ["<missing>", 0], ["SIZE", 213], ["SMNT", 250], ["PORT", 200], ["PASS", 501], ["ABOR", 501], ["STAT", 450], ["HELP", 211], ["APPE", 426], ["QUIT", 221], ["REIN", 421], ["RMD", 530], ["STOU", 110], ["PASV", 501], ["CDUP", 200], ["APPE", 532], ["RNFR", 350], ["SIZE", 500], ["LIST", 530], ["REST", 350], ["SMNT", 202], ["APPE", 421], ["DELE", 250], ["SMNT", 500], ["ABOR", 225], ["STAT", 530], ["STOU", 150], ["STRU", 200], ["ACCT", 530], ["MACB", 550], ["HELP", 200], ["MKD", 502], ["SITE", 500], ["USER", 331], ["DELE", 550], ["LIST", 250], ["MKD", 530], ["ALLO", 421], ["REIN", 502], ["LIST", 502], ["RETR", 421], ["STOR", 421], ["STOU", 425], ["MODE", 502], ["STRU", 504], ["MLST", 500], ["RETR", 550], ["ACCT", 500], ["NLST", 530], ["STOR", 125], ["LIST", 226], ["CWD", 250], ["MODE", 200], ["LIST", 450], ["RETR", 451], ["STOU", 250], ["SYST", 421], ["NOOP", 421], ["MODE", 530], ["QUIT", 0], ["RNTO", 500], ["CDUP", 530], ["USER", 421], ["REST", 421], ["NLST", 501], ["APPE", 250], ["CWD", 421], ["PASV", 421], ["PORT", 530], ["LIST", 426], ["TYPE", 421], ["MKD", 501], ["MODE", 500], ["STOR", 551], ["RETR", 501], ["NOOP", 500], ["APPE", 552], ["USER", 332], ["MLST", 501], ["DELE", 530], ["SYST", 500], ["TYPE", 530], ["ABOR", 502], ["RETR", 110], ["SITE", 200], ["STOR", 501], ["SYST", 215], ["RETR", 426], ["RETR", 530], ["CDUP", 550], ["REIN", 220], ["RNFR", 501], ["STOR", 550], ["RMD", 550], ["CLNT", 500], ["STOU", 501], ["RNFR", 421], ["ABOR", 226], ["SMNT", 421], ["EPSV", 229], ["PORT", 421], ["PWD", 501], ["RETR", 450], ["RMD", 250], ["STOU", 551], ["<init>", 421], ["RNFR", 502], ["RNTO", 501], ["SITE", 530], ["CDUP", 502], ["MKD", 550], ["PASV", 530], ["REIN", 500], ["USER", 500], ["LIST", 501], ["MDTM", 500], ["STRU", 421], ["MODE", 501], ["EPSV", 501], ["ACCT", 501], ["LPRT", 521], ["PASS", 500], ["NLST", 550], ["MLST", 550], ["APPE", 150], ["DELE", 502], ["LIST", 150], ["NLST", 125], ["SMNT", 502], ["STRU", 530], ["APPE", 452], ["MACB", 200], ["ACCT", 230], ["MDTM", 213], ["PASS", 332], ["REST", 200], ["REST", 500], ["CWD", 500], ["HELP", 502], ["EPSV", 500], ["PORT", 501], ["LIST", 425], ["RETR", 250], ["PASS", 530], ["RMD", 421], ["SITE", 214], ["STAT", 212], ["MLSD", 501], ["APPE", 501], ["RNTO", 502], ["SITE", 502], ["STOR", 553], ["RNTO", 421], ["STAT", 421], ["MDTM", 501], ["STOR", 500], ["<init>", 120], ["MKD", 421], ["REIN", 120], ["SIZE", 501], ["STOR", 532], ["PASS", 421], ["STOR", 552], ["STAT", 502], ["ABOR", 421], ["STAT", 213], ["PWD", 500], ["STOR", 452], ["APPE", 451], ["HELP", 214], ["STOR", 530], ["APPE", 551], ["ALLO", 500], ["FEAT", 211], ["NLST", 250], ["QUIT", 500], ["STOR", 450], ["DELE", 450], ["STAT", 501], ["PASS", 230], ["RETR", 226], ["MKD", 257], ["RNTO", 530], ["ALLO", 530], ["STAT", 500], ["STRU", 500], ["PWD", 550], ["SITE", 202], ["NLST", 450], ["STOR", 250], ["LPRT", 501], ["MLSD", 550], ["APPE", 500], ["RNTO", 503], ["SMNT", 501], ["APPE", 553], ["NLST", 150], ["STOU", 552], ["PWD", 421], ["SMNT", 550], ["<init>", 220], ["MACB", 500], ["ACCT", 421], ["EPRT", 522], ["CDUP", 250], ["NLST", 425], ["PASV", 227], ["MLST", 150], ["TYPE", 200], ["REST", 501], ["USER", 501], ["PORT", 500], ["RMD", 500], ["STAT", 211]]
         },
        {"name": "HTTP::foo_bar", "type": "pattern", "doc": "bad stuff", "val": [r"^?((^?(foo)$?)|(^?(bar)$?))$?", r"^?(.|\\n)*((^?(foo)$?)|(^?(bar)$?))"]}
        ]

    def test_notice_config_empty(self):
        val = {'name': "ESnet::notice_cfg", "type": "vector of record { src:set[subnet]; src_in:set[string]; note:set[enum]; action:set[enum]; }",
               'doc': "ESnet notice policies", 'val': []}
        response = self.c.post('/brokerd_api/v1/sensor_option/',
                               {'sensor_uuid': s_uuid, 'options': [val]}, content_type='application/json')
        self.assertTrue(response.json()['success'])
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(models.ZeekContainer.objects.all()), 1)
        ctr = models.ZeekContainer.objects.all()[0]
        self.assertEqual(len(ctr.items.all()), 0)
        response = self.c.get('/sensors/edit_option/1')
        self.assertEqual(response.status_code, 200)

    def test_notice_config(self):
        val = {'name': "ESnet::notice_cfg", "type": "vector of record { src:set[subnet]; src_in:set[string]; note:set[enum]; action:set[enum]; }",
               'doc': "ESnet notice policies", 'val': [[[], [], [], []]]}
        response = self.c.post('/brokerd_api/v1/sensor_option/',
                               {'sensor_uuid': s_uuid, 'options': [val]}, content_type='application/json')
        self.assertTrue(response.json()['success'])
        self.assertEqual(response.status_code, 200)
        ctr = models.ZeekContainer.objects.all()[0]
        print(ctr)
        self.assertEqual(len(models.ZeekContainer.objects.all()), 1)
        self.assertEqual(len(ctr.items.all()), 1)
        response = self.c.get('/sensors/edit_option/1')
        self.assertEqual(response.status_code, 200)

    def test_record(self):
        val = {"sensor_uuid": s_uuid, "options": [{"name": "Exporter::addl_functions", "type": "table[string] of record { arg:int; addl:int; }", "doc": "", "val": {"SumStats::cluster_get_result": [1, -1], "SumStats::cluster_send_result": [1, -1], "conn_weird": [0, 2], "flow_weird": [0, 3], "net_weird": [0, 1]}}]}
        response = self.c.post('/brokerd_api/v1/sensor_option/', val, content_type='application/json')
        self.assertTrue(response.json()['success'])
        self.assertEqual(response.status_code, 200)

    def test_dce_rpc(self):
        val = {'winreg': ["BaseRegGetVersion", "BaseRegCloseKey"]}
        m = models.ZeekVal.create("table[string] of set[string]", val)
        print(m.items.all())


class TestFromServer(TestCase):
    def test_set_enum_of_interval(self):
        v = {"Analyzer::ANALYZER_FTP": 360.0, "Analyzer::ANALYZER_SSH": 3600.0}
        from_json(v, "table[enum] of interval")
