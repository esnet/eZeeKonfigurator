from django.core.exceptions import ValidationError
from django.test import TestCase
from django.urls import reverse
import json
import os
from webconfig import models


class ZeekValTestCase(TestCase):
    model = None

    invalid_types = ["addr", "any", "bool", "count", "double", "enum", "int", "interval", "pattern",
                     "port", "record", "set", "string", "subnet", "table", "time", "vector", "",
                     "integer", "uint", "uint16", "void", "float"]

    valid_in_out = []
    invalid_input = []

    def test_invalid_type(self):
        if not self.model:
            return
        for t in self.invalid_types:
            with self.subTest(type_name=t):
                with self.assertRaises(AssertionError):
                    self.model.create(t, self.valid_in_out[0][0])


class ZeekAtomicValTestCase(ZeekValTestCase):
    type_name = ""

    def test_import_export(self):
        for import_val, export_val in self.valid_in_out:
            with self.subTest(import_val=import_val, export_val=export_val):
                m = models.ZeekVal().create(self.type_name, import_val)
                m.save()
                self.assertEqual(m.zeek_export(), export_val)

    def test_invalid_input(self):
        for i in self.invalid_input:
            with self.subTest(import_val=i):
                with self.assertRaises(ValidationError):
                    m = models.ZeekVal().create(self.type_name, i)
                    m.save()
                    print(m)


class ZeekContainerValTestCase(ZeekValTestCase):
    order_matters = True

    def test_import_export(self):
        if not self.model:
            return
        for type_name, import_val, export_val in self.valid_in_out:
            with self.subTest(import_val=import_val, export_val=export_val):
                m = self.model.create(type_name, import_val)
                m.save()
                if self.order_matters:
                    self.assertEqual(m.zeek_export(), export_val)
                else:
                    self.assertEqual(sorted(m.zeek_export()), sorted(export_val))

    def test_invalid_input(self):
        if not self.model:
            return
        for type_name, i in self.invalid_input:
            with self.subTest(import_val=i):
                try:
                    m = self.model.create(type_name, i)
                    m.save()
                    print(m)
                except (ValidationError, AssertionError, NotImplementedError) as e:
                    with self.assertRaises(ValidationError):
                        raise ValidationError(e)

    def test_invalid_type(self):
        return


class ZeekBoolTestCase(ZeekAtomicValTestCase):
    type_name = "bool"

    valid_in_out = [
        ("T", "T"),
        ("F", "F"),
        (True, "T"),
        (False, "F"),
    ]

    invalid_input = [
        "True", "False", "t", "f", "true", "false",
        "1", "0", "1 == 1", "OR True",
        "Tru", "Falsee", ""
    ]

            
class ZeekIntTestCase(ZeekAtomicValTestCase):
    type_name = "int"

    valid_in_out = [
        ("1234567890", "1234567890"),
        ("001234567890", "1234567890"),
        ("-9999999999", "-9999999999"),
        ("-0", "0"),
        ("+123", "123"),
    ]

    invalid_input = [
        "T", "F", "one", "",
        "1.0", "0.0", "0x120", "0b111", "1e12",
        "12345678901234567890", "-12345678901234567890",
        "--123", "-+123", "+-123", "++123",
    ]


class ZeekCountTestCase(ZeekAtomicValTestCase):
    type_name = "count"

    valid_in_out = [
        ("12345678901234567890", "12345678901234567890"),
        ("1234567890", "1234567890"),
        ("001234567890", "1234567890"),
        ("-0", "0"),
        ("+123", "123"),
    ]

    invalid_input = [
        "T", "F", "one", "",
        "1.0", "0.0", "0x120", "0b111", "1e12",
        "-1", "-12345678901234567890", "--0",
    ]


class ZeekDoubleTestCase(ZeekAtomicValTestCase):
    type_name = "double"

    valid_in_out = [
        ("0.12345", "0.12345"),
        ("-8675309.867531", "-8675309.867531"),
        ("198721", "198721.0"),
        (".123", "0.123"),
        (".123000", "0.123"),
        ("1.0000", "1.0"),
        ("9.99e+27", "9.99e+27"),
        ("9.99e-27", "9.99e-27"),
        ("-9.99e+27", "-9.99e+27"),
        ("-9.99e-27", "-9.99e-27"),

    ]

    invalid_input = [
        "0x120", "0b120",
        "--123", "-+123", "+-123", "++123",
        "0..0", "0.0.0",
    ]


class ZeekTimeTestCase(ZeekAtomicValTestCase):
    type_name = "time"

    valid_in_out = [
        ("1569334218", "1569334218.0"),
        ("1569334218.0", "1569334218.0"),
        ("1569334218.0000", "1569334218.0"),
        ("1569334218.1234", "1569334218.1234"),
        ("-1569334218", "-1569334218.0"),
        ("-1569334218.0", "-1569334218.0"),
        ("-1569334218.0000", "-1569334218.0"),
        ("-1569334218.1234", "-1569334218.1234"),
    ]

    invalid_input = ZeekDoubleTestCase.invalid_input + [
        "9.99e+27",
        "-9.99e+27",
    ]


class ZeekIntervalTestCase(ZeekAtomicValTestCase):
    type_name = "interval"

    valid_in_out = [
        ("30.0 sec", "30.0"),
        ("-30.0 sec", "-30.0"),
        ("30.0 secs", "30.0"),
        ("30 sec", "30.0"),

        ("1.5 mins", "90.0"),
        ("2.0 min", "120.0"),
        ("2.0 hrs", "7200.0"),
        ("2.0 days", "172800.0"),

        ("0.0 usec", "0.0"),
        ("0.0 msec", "0.0"),
        ("0.0 sec", "0.0"),
        ("0.0 min", "0.0"),
        ("0.0 hr", "0.0"),
        ("0.0 day", "0.0"),

        ("1.0 usec", "0.000001"),
        ("1.0 usecs", "0.000001"),
        ("1.0 msec", "0.001"),
        ("1.0 msecs", "0.001"),
        ("1.0 sec", "1.0"),
        ("1.0 secs", "1.0"),

        ("1.0 min", "60.0"),
        ("1.0 mins", "60.0"),
        ("1.0 hr", "3600.0"),
        ("1.0 hrs", "3600.0"),
        ("1.0 day", "86400.0"),
        ("1.0 days", "86400.0"),

        ("-1.0 usec", "-0.000001"),
        ("-1.0 msec", "-0.001"),
        ("-1.0 sec", "-1.0"),
        ("-1.0 min", "-60.0"),
        ("-1.0 hr", "-3600.0"),
        ("-1.0 day", "-86400.0"),

        ("7.0 days 6.0 hrs 5.0 min 4.0 secs 3.0 msec 2.0 usecs", "626704.003002"),
        ("-7.0 days -6.0 hrs -5.0 min -4.0 secs -3.0 msec -2.0 usecs", "-626704.003002"),
    ]

    invalid_input = [
        "0s", "0.0s", "0.0", "1", "",

        "1.0 sec 2.0 sec 3.0 secs",
        "1.0 sec 2.0 min 3.0 hr",
        "1.0 day 2.0 hrs 1.0 day",

        "1234.0"
    ]


class ZeekStringTestCase(ZeekAtomicValTestCase):
    type_name = "string"

    valid_in_out = [
        ("", '""'),
        ("abc", '"abc"'),
        ("'abc'", "\"'abc'\""),
        ("'abc", "\"'abc\""),
        ('"abc', '""abc"'),

        # String escaping
        (r"a\x09y", '"a\\x09y"'),
        (r"a\x0d\x0a\x08b", '"a\\x0d\\x0a\\x08b"'),
        (r"foo\x00bar", '"foo\\x00bar"')
    ]

    invalid_input = [
        "\u1234",
    ]


class ZeekPortTestCase(ZeekAtomicValTestCase):
    type_name = "port"

    valid_in_out = [
        ({"port": 0, "proto": "tcp"}, "0/tcp"),
        ({"port": -0, "proto": "tcp"}, "0/tcp"),
        ({"port": 65535, "proto": "tcp"}, "65535/tcp"),
        ({"port": 1234, "proto": "udp"}, "1234/udp"),
        ({"port": 255, "proto": "icmp"}, "255/icmp"),
    ]

    invalid_input = [
        "0/0", "0/sctp", "1/1/tcp", "1/", "/tcp",
        "256/icmp", "65535/icmp",
        "-1/tcp", "-2/icmp",
        "0.0/tcp", "0/tdp", "0/ucp", "0/icp"
    ]


class ZeekAddrTestCase(ZeekAtomicValTestCase):
    type_name = "addr"

    valid_in_out = [
        ("0.0.0.0", "0.0.0.0"),
        ("127.0.0.1", "127.0.0.1"),
        ("255.255.255.255", "255.255.255.255"),
        ("12.34.123.234", "12.34.123.234"),

        ("::", "::"),
        ("1200:0000:AB00:1234:0000:2552:7777:1313", "1200:0000:AB00:1234:0000:2552:7777:1313"),
        ("21DA:D3:0:2F3B:2AA:FF:FE28:9C5A", "21DA:D3:0:2F3B:2AA:FF:FE28:9C5A"),
        ("fFfF::", "FFFF::"),
    ]

    invalid_input = [
        "0.0.0.256", "1.2.3.4.5", "1.2.3", ".1.2.3", "1..2.3.4",
        "1200::AB00:1234::2552:7777:1313", "1200:0000:AB00:1234:XXXX:2552:7777:1313"
    ]


class ZeekSubnetTestCase(ZeekAtomicValTestCase):
    type_name = "subnet"

    valid_in_out = [
        ("0.0.0.0/0", "0.0.0.0/0"),
        ("0.0.0.0/1", "0.0.0.0/1"),
        ("0.0.0.0/16", "0.0.0.0/16"),
        ("1.2.3.4/15", "1.2.0.0/15"),

        ("127.0.0.1/32", "127.0.0.1/32"),
        ("255.255.255.255/32", "255.255.255.255/32"),
        ("12.34.123.0/27", "12.34.123.0/27"),

        ("::/128", "[::]/128"),
        ("1200:0000:AB00:1234:0000:2552:7777:1313/64", "[1200:0:ab00:1234::]/64"),
        ("21DA:D3:0:2F3B:2AA:FF:FE28:9C5A/88", "[21da:d3:0:2f3b:2aa::]/88"),
        ("fFfF::/12", "[fff0::]/12"),
    ]

    invalid_input = ZeekAddrTestCase.invalid_input + \
                    ["%s/1" % i for i in ZeekAddrTestCase.invalid_input] + \
                    [i for i, e in ZeekAddrTestCase.valid_in_out] + \
                    [
        "0.0.0.0/0.0",
        "0.0.0.0/any",
        "0.0.0.0/1e1",
        "0.0.0.0/0x12",
        "0.0.0.0/b10",

        "0.0.0.0/-0",
        "0.0.0.0/+0",
        "0.0.0.0/-1",
        "1.2.3.4/33",
    ]


class ZeekEnumTestCase(ZeekAtomicValTestCase):
    type_name = "enum"

    valid_in_out = [
        ("Analyzer::ANALYZER_SYSLOG", "Analyzer::ANALYZER_SYSLOG"),
        ("Green", "Green"),
    ]

    invalid_input = [
        "", "Analyzer::Analyzer::ANALYZER_SYSLOG", "abc:", "Analyzer::$3"
    ]


class ZeekSetTestCase(ZeekContainerValTestCase):
    model = models.ZeekSet
    order_matters = False

    valid_in_out = [
        ("set[string]", {"1", "2", "3"}, '{"1", "2", "3"}'),
        # ("set[string]", "{1}", "{1}"),
        # ("set[string]", "{}", "{}"),
        # ("set[string]", "{a, b, c}", "{a, b, c}"),
        # ("set[count]", "{1, 2, 3}", "{1, 2, 3}"),
        # ("set[int]", "{1, 0, -1}", "{1, 0, -1}"),
        # ("set[set[int]]", "{{0, 1}, {1, 2}}", "{{0, 1}, {1, 2}}"),
    ]

    invalid_input = [
        ("set[string]", {1, 2}),
    ]


class ZeekTableTestCase(ZeekContainerValTestCase):
    model = models.ZeekTable

    valid_in_out = [
        ("table[count] of string", {"1":"one","2":"two"}, '{[1] = "one", [2] = "two"}'),
        ("table[count] of bool", {"1":"T","2":"F"}, '{[1] = T, [2] = F}'),
        ("table[bool] of bool", {"T":"T","F":"F"}, '{[T] = T, [F] = F}'),
    ]


class ZeekTestImport(TestCase):
    filename = os.path.join(os.path.dirname(__file__), "test_data/site_local.opts")
    opts = {}

    def setUp(self):
        with open(self.filename) as f:
            self.opts = json.loads(f.readline())['data']['options']

    def run_for_type(self, t):
        for k, v in self.opts.items():
            if v['type_name'].startswith(t):
                with self.subTest(opt=k, val=v['value']):
                    m = models.ZeekVal.create(v['type_name'], v['value'])
                    m.save()

    def test_bool(self):
        self.run_for_type('bool')

    def test_count(self):
        self.run_for_type('count')

    def test_string(self):
        self.run_for_type('string')

    def test_enum(self):
        self.run_for_type('enum')

    def test_interval(self):
        self.run_for_type('interval')

    def test_int(self):
        self.run_for_type('int')

    def test_double(self):
        self.run_for_type('double')

    def test_table(self):
        self.run_for_type('table[')

    def test_set(self):
        self.run_for_type('set[')

    def test_vector(self):
        self.run_for_type('vector of ')

    @staticmethod
    def index_type_checked(index_type, composite_types):
        for c in composite_types:
            if index_type.startswith(c):
                return True
        return False

    def test_z_items_left(self):
        parsed_atomic_types = ['bool', 'count', 'string', 'enum', 'interval', 'int', 'double']
        parsed_composite_types = ['table[', 'set[', 'vector of ']

        unparsed_atomics = [v['type_name'] for k, v in self.opts.items() if v['type_name'] not in parsed_atomic_types]
        unparsed = [i for i in unparsed_atomics if not self.index_type_checked(i, parsed_composite_types)]

        print("\n".join(unparsed))

        self.assertEqual(len(unparsed), 0)


class SensorModel(TestCase):
    uuid = "86439f94-0b58-41c0-bb49-78aef523189d"

    def test_create_or_get_like_brokerd_api(self):
        params = {
                'uuid': self.uuid,
                'zeek_version': "3.0.0-222",
                'hostname': "zeek-prod.example.net",
        }
        s, created = models.Sensor.objects.get_or_create(**params)
        s.save()
        self.assertEqual(created, True)
        self.assertEqual(s.uuid, self.uuid)


class BrokerDaemonAPI(TestCase):
    uuid = "86439f94-0b58-41c0-bb49-78aef523189d"

    def setUp(self):
        models.BrokerDaemon.objects.create(uuid=self.uuid, authorized=True, ip='127.0.0.1', port=47750).save()

    def test_sensor_create(self):
        sensor_data = {'sensor_uuid': '8099ee53-bbd9-4e1b-86f8-86a7f86612de', 'zeek_version': '3.0.0-25', 'hostname': 'bro-cmi.example.net'}
        response = self.client.post(reverse('sensor_info', kwargs={'brokerd_uuid': self.uuid, 'ver': 1}), json.dumps(sensor_data),
                                    content_type="application/json")
        print(response.json())
        self.assertEqual(response.status_code, 200)