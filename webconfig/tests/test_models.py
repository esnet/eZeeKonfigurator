import datetime
import json

from django.core.exceptions import ValidationError
from django.test import TestCase
from django.urls import reverse

from broker_json.utils import get_index_types, get_yield_type
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
                # TODO: This was updated because abstract base classes can't be instantiated.
                # Investigate if there's a cleaner way to do this.
                m = models.get_model_for_type(self.type_name).create(
                    self.type_name, import_val)
                m.save()
                self.assertEqual(m.zeek_export(), export_val)

    def test_invalid_input(self):
        for i in self.invalid_input:
            with self.subTest(import_val=i):
                with self.assertRaises(ValidationError):
                    # Same as above TODO
                    m = models.get_model_for_type(self.type_name).create(
                        self.type_name, i)
                    m.save()


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
                    for i in m.zeek_export():
                        self.assertEqual(m.zeek_export(), export_val)
                        self.assertIn(i, export_val)

    def test_invalid_input(self):
        if not self.model:
            return
        for type_name, i in self.invalid_input:
            with self.subTest(import_val=i):
                try:
                    m = self.model.create(type_name, i)
                    m.save()
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
        "t", "f",
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

        (1234567890, "1234567890"),
        (-9999999999, "-9999999999"),
        (-0, "0"),
        (+123, "123"),
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

        (12345678901234567890, "12345678901234567890"),
        (1234567890, "1234567890"),
        (1234567890, "1234567890"),
        (-0, "0"),
        (+123, "123"),

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

        (0.12345, "0.12345"),
        (-8675309.867531, "-8675309.867531"),
        (198721, "198721.0"),
        (.123, "0.123"),
        (.123000, "0.123"),
        (1.0000, "1.0"),
        (9.99e+27, "9.99e+27"),
        (9.99e-27, "9.99e-27"),
        (-9.99e+27, "-9.99e+27"),
        (-9.99e-27, "-9.99e-27"),

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

        (1569334218, "1569334218.0"),
        (1569334218.0, "1569334218.0"),
        (1569334218.0000, "1569334218.0"),
        (1569334218.1234, "1569334218.1234"),
        (-1569334218, "-1569334218.0"),
        (-1569334218.0, "-1569334218.0"),
        (-1569334218.0000, "-1569334218.0"),
        (-1569334218.1234, "-1569334218.1234"),
    ]

    invalid_input = ZeekDoubleTestCase.invalid_input + [
        "9.99e+27",
        "-9.99e+27",
    ]


class ZeekIntervalTestCase(ZeekAtomicValTestCase):
    type_name = "interval"

    valid_in_out = [
        ("30.0", "30.0"),
        ("-30.0", "-30.0"),
        ("30", "30.0"),

        ("90", "90.0"),
        ("120", "120.0"),
        ("7200", "7200.0"),
        ("172800.00", "172800.0"),
        ("0.000001", "0.000001"),
        ("0.001", "0.001"),
        ("1", "1.0"),

        ("-90", "-90.0"),
        ("-120", "-120.0"),
        ("-7200", "-7200.0"),
        ("-172800.00", "-172800.0"),
        ("-0.000001", "-0.000001"),
        ("-0.001", "-0.001"),
        ("-1", "-1.0"),

        (datetime.timedelta(seconds=-90), "-90.0"),
        (datetime.timedelta(minutes=2), "120.0"),
        (datetime.timedelta(hours=-2), "-7200.0"),
    ]

    invalid_input = [
        "0s", "0.0s", "",

        "1.0 sec 2.0 sec 3.0 secs",
        "1.0 sec 2.0 min 3.0 hr",
        "1.0 day 2.0 hrs 1.0 day",
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
    ]


class ZeekPortTestCase(ZeekAtomicValTestCase):
    type_name = "port"

    valid_in_out = [
        ({"port": 0, "proto": "tcp"}, "0/tcp"),
        ({"port": -0, "proto": "tcp"}, "0/tcp"),
        ({"port": 65535, "proto": "tcp"}, "65535/tcp"),
        ({"port": 1234, "proto": "udp"}, "1234/udp"),
        ({"port": 255, "proto": "icmp"}, "255/icmp"),
        ({"port": 123}, "123/?"),
        ("0/tcp", "0/tcp"),
        ("-0/tcp", "0/tcp"),
        ("65535/tcp", "65535/tcp"),
        ("1234/udp", "1234/udp"),
        ("255/icmp", "255/icmp"),
        ("123/unknown", "123/?"),

    ]

    invalid_input = [
        "1/1/tcp", "/tcp",
        "256/icmp", "65535/icmp",
        "-1/tcp", "-2/icmp",
        "0.0/tcp", "0/",
        "22/sctp"
    ]


class ZeekAddrTestCase(ZeekAtomicValTestCase):
    type_name = "addr"

    valid_in_out = [
        ("0.0.0.0", "0.0.0.0"),
        ("127.0.0.1", "127.0.0.1"),
        ("255.255.255.255", "255.255.255.255"),
        ("12.34.123.234", "12.34.123.234"),

        ("::", "::"),
        ("1200:0000:AB00:1234:0000:2552:7777:1313", "1200:0:ab00:1234:0:2552:7777:1313"),
        ("21DA:D3:0:2F3B:2AA:FF:FE28:9C5A", "21da:d3:0:2f3b:2aa:ff:fe28:9c5a"),
        ("fFfF::", "ffff::"),
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

        ("::/128", "::/128"),
        ("1200:0000:AB00:1234:0000:2552:7777:1313/64", "1200:0:ab00:1234::/64"),
        ("21DA:D3:0:2F3B:2AA:FF:FE28:9C5A/88", "21da:d3:0:2f3b:2aa::/88"),
        ("fFfF::/12", "fff0::/12"),
    ]

    invalid_input = ZeekAddrTestCase.invalid_input + \
                    ["%s/1" % i for i in ZeekAddrTestCase.invalid_input] + \
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


class ZeekPatternTestCase(ZeekAtomicValTestCase):
    type_name = "pattern"

    exact_format = "^?(%s)$?"
    anywhere_format = "^?(.|\\n)*(%s)"

    def test_add_exact_foo(self):
        p = "foo"
        m = models.ZeekVal.create("pattern", [self.exact_format % p, self.anywhere_format % p])
        m.save()
        self.assertEqual(str(m), "/foo/")

    def test_add_exact_foo_bar(self):
        m = models.ZeekVal.create("pattern", [r"^?((^?(foo)$?)|(^?(bar)$?))$?", r"^?(.|\\n)*((^?(foo)$?)|(^?(bar)$?))"])
        m.save()
        self.assertEqual(str(m), "/foo/ | /bar/")
        self.assertEqual(3, models.ZeekPattern.objects.all().count())
        self.assertEqual(2, models.ZeekContainerItem.objects.all().count())


    def test_add_foo_or_bar(self):
        p = "foo|bar"
        m = models.ZeekVal.create("pattern", [self.exact_format % p, self.anywhere_format % p])
        m.save()
        self.assertEqual(str(m), "/foo|bar/")

    def test_parse_exact_foo_bar(self):
        m = models.ZeekPattern()
        self.assertEqual(m.get_exact_parts(r"^?(foo)$?"), ["foo"])
        self.assertEqual(m.get_exact_parts(r"^?((^?(foo)$?)|(^?(bar)$?))$?"), ["foo", "bar"])
        self.assertEqual(m.get_exact_parts(r"^?((^?((^?(foo)$?)|(^?(bar)$?))$?)|(^?(baz)$?))$?"), ["foo", "bar", "baz"])
        self.assertEqual(m.get_exact_parts(r"^?((^?((^?((^?((^?(foo)$?)|(^?(bar)$?))$?)|(^?(baz)$?))$?)|(^?(qux)$?))$?)|(^?(quuz)$?))$?"),
                         ['foo', 'bar', 'baz', 'qux', 'quuz'])
        self.assertEqual(m.get_exact_parts(r"^?((^?((^?((^?((^?((^?((^?((^?((^?((^?((^?((^?((^?(foo)$?)|(^?(bar)$?))$?)|(^?(baz)$?))$?)|(^?(qux)$?))$?)|(^?(quuz)$?))$?)|(^?(corge)$?))$?)|(^?(grault)$?))$?)|(^?(garply)$?))$?)|(^?(waldo)$?))$?)|(^?(fred)$?))$?)|(^?(plugh)$?))$?)|(^?(xyzzy)$?))$?)|(^?(thud)$?))$?"),
                         ['foo', 'bar', 'baz', 'qux', 'quuz', 'corge', 'grault', 'garply', 'waldo', 'fred', 'plugh', 'xyzzy', 'thud'])

    valid_in_out = [(["^?(\/playground\/init\/login\/validate)$?", "^?(.|\n)*(\/playground\/init\/login\/validate)"], r"/\/playground\/init\/login\/validate/")]


# class ZeekSetTestCase(ZeekContainerValTestCase):
#     model = models.ZeekSet
#     order_matters = False
#
#     valid_in_out = [
#         ("set[string]", ["1", "2", "3"], '{"1", "2", "3"}'),
#         # ("set[string]", "{1}", "{1}"),
#         # ("set[string]", "{}", "{}"),
#         # ("set[string]", "{a, b, c}", "{a, b, c}"),
#         # ("set[count]", "{1, 2, 3}", "{1, 2, 3}"),
#         # ("set[int]", "{1, 0, -1}", "{1, 0, -1}"),
#         # ("set[set[int]]", "{{0, 1}, {1, 2}}", "{{0, 1}, {1, 2}}"),
#     ]
#
#     invalid_input = [
#         ("set[string]", {1, 2}),
#     ]
#
#
# class ZeekTableTestCase(ZeekContainerValTestCase):
#     model = models.ZeekTable
#
#     valid_in_out = [
#         ("table[count] of string", {"1":"one","2":"two"}, '{[1] = "one", [2] = "two"}'),
#         ("table[count] of bool", {"1":"T","2":"F"}, '{[1] = T, [2] = F}'),
#         ("table[bool] of bool", {"T":"T","F":"F"}, '{[T] = T, [F] = F}'),
#     ]
#
#     def test_parse(self):
#         m = self.model().parse("table[count, port] of string", None)
#         self.assertEqual(m['index_types'], 'count, port')
#         self.assertEqual(m['yield_type'], 'string')
#
#     def test_create_empty_directly(self):
#         kwargs = self.model().parse("table[count, port] of string", {})
#         m = self.model(**kwargs)
#         m.save()
#
#         self.assertEqual(m.index_types, 'count, port')
#         self.assertEqual(m.yield_type, 'string')
#
#     def test_create_empty_top(self):
#         m = models.ZeekVal.create("table[count, port] of string", {})
#         self.assertEqual(str(m), "{}")
#
#     def test_create_simple_empty(self):
#         m = models.ZeekVal.create("table[count] of string", {1: 'one'})
#         self.assertEqual(str(m), "{[1] = \"one\"}")
#

# class ZeekTestImport(TestCase):
#     filename = os.path.join(os.path.dirname(__file__), "test_data/site_local.opts.json")
#     opts = {}
#
#     def setUp(self):
#         with open(self.filename) as f:
#             self.opts = json.loads(f.readline())['data']['options']
#
#     def run_for_type(self, t):
#         for k, v in self.opts.items():
#             if v['type_name'].startswith(t):
#                 with self.subTest(opt=k, val=v['value']):
#                     m = models.ZeekVal.create(v['type_name'], v['value'])
#                     m.save()
#
#     def test_bool(self):
#         self.run_for_type('bool')
#
#     def test_count(self):
#         self.run_for_type('count')
#
#     def test_string(self):
#         self.run_for_type('string')
#
#     def test_enum(self):
#         self.run_for_type('enum')
#
#     def test_interval(self):
#         self.run_for_type('interval')
#
#     def test_int(self):
#         self.run_for_type('int')
#
#     def test_double(self):
#         self.run_for_type('double')
#
#     def test_table(self):
#         self.run_for_type('table[')
#
#     def test_set(self):
#         self.run_for_type('set[')
#
#     def test_vector(self):
#         self.run_for_type('vector of ')
#
#     @staticmethod
#     def index_type_checked(index_type, composite_types):
#         for c in composite_types:
#             if index_type.startswith(c):
#                 return True
#         return False
#
#     def test_z_items_left(self):
#         parsed_atomic_types = ['bool', 'count', 'string', 'enum', 'interval', 'int', 'double']
#         parsed_composite_types = ['table[', 'set[', 'vector of ']
#
#         unparsed_atomics = [v['type_name'] for k, v in self.opts.items() if v['type_name'] not in parsed_atomic_types]
#         unparsed = [i for i in unparsed_atomics if not self.index_type_checked(i, parsed_composite_types)]
#
#         print("\n".join(unparsed))
#
#         self.assertEqual(len(unparsed), 0)


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
    zs_uuid = "8099ee53-bbd9-4e1b-86f8-86a7f86612de"

    def test_sensor_create(self):
        sensor_data = {'sensor_uuid': self.zs_uuid, 'zeek_version': '3.0.0-25', 'hostname': 'bro-cmi.example.net'}
        response = self.client.post(reverse('sensor_info', kwargs={'ver': 1}), json.dumps(sensor_data),
                                    content_type="application/json")
        self.assertEqual(response.status_code, 200)

    def test_count_import(self):
        self.test_sensor_create()
        options = [{'name': "Default::timeout", 'type': 'int', 'val': 3, 'doc': None}]

        data = {'sensor_uuid': self.zs_uuid, 'options': options}
        response = self.client.post(reverse('sensor_option', kwargs={'ver': 1}),
                                    json.dumps(data),
                                    content_type="application/json")
        self.assertEqual(response.status_code, 200)

    def test_update_count(self):
        self.test_sensor_create()
        options = [
            {'name': "Default::timeout", 'type': 'int', 'val': 3, 'doc': None},
            {'name': "Default::timeout", 'type': 'int', 'val': 1, 'doc': None},
            {'name': "Default::timeout", 'type': 'int', 'val': 1, 'doc': None},
        ]

        for o in options:
            data = {'sensor_uuid': self.zs_uuid, 'options': [o]}
            response = self.client.post(reverse('sensor_option', kwargs={'ver': 1}),
                                    json.dumps(data),
                                    content_type="application/json")
            self.assertEqual(response.status_code, 200)

        # Check that we didn't create duplicates
        self.assertEqual(models.Setting.objects.all().count(), 1)
        self.assertEqual(models.Option.objects.all().count(), 1)

        # Check that we have the right value
        self.assertEqual(str(models.Setting.objects.all()[0]), "Default::timeout = 1")

    def test_update_bool(self):
        self.test_sensor_create()
        options = [
            {'name': "Default::timeout", 'type': 'bool', 'val': False, 'doc': None},
            {'name': "Default::timeout", 'type': 'bool', 'val': True, 'doc': None},
            {'name': "Default::timeout", 'type': 'bool', 'val': True, 'doc': None},
        ]

        for o in options:
            data = {'sensor_uuid': self.zs_uuid, 'options': [o]}
            response = self.client.post(reverse('sensor_option', kwargs={'ver': 1}),
                                        json.dumps(data), content_type="application/json")
            self.assertEqual(response.status_code, 200)

        # Check that we didn't create duplicates
        self.assertEqual(models.Setting.objects.all().count(), 1)
        self.assertEqual(models.Option.objects.all().count(), 1)

        # Check that we have the right value
        self.assertEqual(str(models.Setting.objects.all()[0]), "Default::timeout = True")


class ZeekRecordTestCase(TestCase):

    def test_simple_parse(self):
        m = models.ZeekRecord().parse("record { arg:int; addl:int; }", "blah")
        self.assertEqual(m, {'field_types': "record { arg:int; addl:int; }"})

    def test_complex_parse(self):
        m = models.ZeekRecord().parse("record { src:set[subnet]; src_in:set[string]; note:set[enum]; action:set[enum]; }", "blah")
        self.assertEqual(m, {'field_types': "record { src:set[subnet]; src_in:set[string]; note:set[enum]; action:set[enum]; }"})

    def test_create(self):
        m = models.ZeekVal.create('record { arg:int; addl:int; }', [1, -1])
        self.assertEqual(str(m), "[$arg = 1, $addl = -1]")

    def test_create_table_of(self):
        m = models.ZeekVal.create('table[count] of record { arg:int; addl:int; }', {1: [1, -1]})
        self.assertEqual(str(m), "{[1] = [$arg = 1, $addl = -1]}")

    def test_serialization(self):
        m = models.ZeekVal.create('record { arg:int; addl:int; }', [1])
        self.assertEqual(m.json(), [1, None])


class CompositeTestCase(TestCase):
    def test_set_easy(self):
        val = [10, 20, 30, 40, 50, 60, 70]
        val_type = 'count'

        m = models.ZeekVal.create("set[%s]" % val_type, val)
        self.assertEqual(m.type_name, 'set[count]')
        self.assertEqual(m.index_types, "['%s']" % val_type)
        self.assertIsNone(m.yield_type)
        self.assertEqual(len(m.items.all()), len(val))

        self.assertEqual(str(m), "{10, 20, 30, 40, 50, 60, 70}")

        for v in val:
            self.assertEqual(len(models.ZeekVal.filter(val_type, v)), 1)

    def test_set_easy_jump(self):
        val = [1, 2, 3, 4, 5, 6, 7, 10, 15, 90, 100, 150, 800, 18201, 1729071]
        val_type = 'count'

        m = models.ZeekVal.create("set[%s]" % val_type, val)
        self.assertEqual(m.type_name, 'set[count]')
        self.assertEqual(m.index_types, "['%s']" % val_type)
        self.assertIsNone(m.yield_type)
        self.assertEqual(len(m.items.all()), len(val))

        for v in val:
            self.assertEqual(len(models.ZeekVal.filter(val_type, v)), 1)

        self.assertEqual(str(m), "{1, 2, 3, 4, 5, 6, 7, 10, 15, 90, ...and 5 more elements...}")


    def test_set_update(self):
        m = models.ZeekVal.create("set[count]", [1, 2])
        m.save()
        self.assertEqual(str(m), "{1, 2}")
        m.items.all()[0].delete()
        self.assertEqual(str(m), "{2}")
        m.v = "[3, 4, 5]"
        m.save()
        self.assertEqual(str(m), "{3, 4, 5}")
        m.v = "1"
        m.save()
        self.assertEqual(str(m), "{1}")
        m.v = "1, 2, 3, 5, 5, 5"
        m.save()
        self.assertEqual(str(m), "{1, 2, 3, 5}")


    def test_set_medium(self):
        m = models.ZeekVal.create("set[count, enum, port, addr, subnet]", [[1, "Notice::ALARM", "22/tcp", "::1", "0.0.0.0/0"]])
        self.assertEqual(m.type_name, 'set[count, enum, port, addr, subnet]')
        self.assertEqual(m.index_types, "['count', 'enum', 'port', 'addr', 'subnet']")
        self.assertIsNone(m.yield_type)
        self.assertEqual(len(m.items.all()), 1)

        self.assertEqual(len(models.ZeekVal.filter('count', 1)), 1)
        self.assertEqual(len(models.ZeekVal.filter('enum', "Notice::ALARM")), 1)
        self.assertEqual(len(models.ZeekVal.filter('port', "22/tcp")), 1)
        self.assertEqual(len(models.ZeekVal.filter('addr', "::1")), 1)
        self.assertEqual(len(models.ZeekVal.filter('subnet', "0.0.0.0/0")), 1)

        self.assertEqual(str(m), "{[1, Notice::ALARM, 22/tcp, ::1, 0.0.0.0/0]}")

    def test_set_hard(self):
        m = models.ZeekVal.create("set[record { arg:int; addl:int; }, record { nested:record { arg1:int; arg2:int; }; arg2:port; }]", [])
        self.assertEqual(m.type_name, 'set[record { arg:int; addl:int; }, record { nested:record { arg1:int; arg2:int; }; arg2:port; }]')
        self.assertEqual(m.index_types, "['record { arg:int; addl:int; }', 'record { nested:record { arg1:int; arg2:int; }; arg2:port; }']")
        self.assertIsNone(m.yield_type)

    def test_vector_easy(self):
        m = models.ZeekVal.create("vector of count", [1, 2, 3, 4, 5])
        self.assertEqual(str(m), "[1, 2, 3, 4, 5]")

    def test_vector_medium(self):
        m = models.ZeekVal.create("vector of port", ["21/tcp", "22/tcp", "53/udp", "8080/udp", "255/icmp"])
        self.assertEqual(str(m), "[21/tcp, 22/tcp, 53/udp, 8080/udp, 255/icmp]")

    def test_table_easy(self):
        m = models.ZeekVal.create("table[count] of string", {1: "one", 2: "two"})
        self.assertEqual(str(m), '{[1] = one, [2] = two}')

    def test_table_medium(self):
        m = models.ZeekVal.create("table[count, enum, port, addr, subnet] of interval", {(1, "Notice::ALARM", "22/tcp", "::1", "0.0.0.0/0"): 30.0})
        self.assertEqual(str(m), '{[1, Notice::ALARM, 22/tcp, ::1, 0.0.0.0/0] = 30.0}')

    def test_table_of_table(self):
        type_name = "table[count] of table[string] of interval"
        self.assertEqual(get_index_types(type_name), ["count"])
        self.assertEqual("table[string] of interval", get_yield_type(type_name))
        m = models.ZeekVal.create(type_name, {1: {"one": 1.0}})
        self.assertEqual(str(m), '{[1] = {[one] = 1.0}}')

    def test_table_hard(self):
        m = models.ZeekVal.create(
            "table[count, enum, port, addr, subnet] of table[count, enum, port, addr, subnet] of interval",
            {(1, "Notice::ALARM", "22/tcp", "::1", "0.0.0.0/0"): {(2,
                                                                   "Notice::PAGE",
                                                                   "80/udp",
                                                                   "2600::1",
                                                                   "127.0.0.1/32"): 86400}})
        self.assertEqual(str(m),
                         '{[1, Notice::ALARM, 22/tcp, ::1, 0.0.0.0/0] = {[2, Notice::PAGE, 80/udp, 2600::1, 127.0.0.1/32] = 86400.0}}')

    def test_truncation(self):
        m = models.ZeekVal.create("set[count]", [x for x in range(1000)])
        self.assertEqual(str(m),
                         "{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, ...and 990 more elements...}")

    def test_offset(self):
        m = models.ZeekVal.create("set[count]", [x for x in range(1000)])
        self.assertEqual(m.__str__(10, 10),
                         "{10, 11, 12, 13, 14, 15, 16, 17, 18, 19, ...and 980 more elements...}")

    def test_vector_json(self):
        l = [1, 2, 3, 4]
        m = models.ZeekVal.create("vector of count", l)
        self.assertEqual(l, m.json())

        l = [0.1, 0.2, 0.3, 0.4]
        m = models.ZeekVal.create("vector of double", l)
        self.assertEqual(l, m.json())

        l = ["a", "b", "c", "d"]
        m = models.ZeekVal.create("vector of string", l)
        self.assertEqual(l, m.json())

    def test_table_json(self):
        l = {'one': 1, 'two': 2}
        m = models.ZeekContainer.create("table[string] of count", l)
        self.assertEqual({'one': 1, 'two': 2}, m.json())

        l = {('one', "22/tcp"): 1, ('two', "80/tcp"): 2}
        m = models.ZeekContainer.create("table[string, port] of count", l)
        self.assertEqual({'["one", "22/tcp"]': 1, '["two", "80/tcp"]': 2},
                         m.json())
