from django.test import TestCase

from eZeeKonfigurator.utils import *
from webconfig import models


class TestUtilsJSON(TestCase):
    valid_to_json = valid_from_json = []

    def test_to_json(self):
        for i, o in self.valid_to_json:
            with self.subTest(py_val=i, json_val=o):
                self.assertEqual(to_json(i), o)

    def test_to_json_dump(self):
        for i, o in self.valid_to_json:
            with self.subTest(py_val=i):
                json.dumps(to_json(i))

    def test_from_json(self):
        for i, o, type_name in self.valid_from_json:
            with self.subTest(json_val=i, py_val=o):
                self.assertEqual(from_json(i, type_name), o)


class TestNativeTypesSerialization(TestUtilsJSON):
    valid_to_json = [(x, x) for x in [
        None,
        True,
        False,
        "abc",
        "",
        "\x01\x02\x00\x12",
        0.00001,
        1.0,
        1e17,
        -0.1,
        -1,
        0,
    ]]

    valid_from_json = [(x, x, t) for x, t in [
        (None, None),
        (True, "bool"),
        (False, "bool"),
        ("abc", "string"),
        ("", "string"),
        ("\x01\x02\x00\x12", "string"),
        (0.00001, "double"),
        (1.0, "double"),
        (1e17, "double"),
        (-0.1, "double"),
        (-1, "int"),
        (0, "int"),
        (b"abc", "string"),
        (b"\u0000", "string"),
    ]]


class TestTimeSerialization(TestUtilsJSON):
    valid_to_json = [(datetime.datetime.fromtimestamp(x), float(x)) for x in [
        0,
        1570034743.559633,
        -1570034743.559633
    ]]

    valid_from_json = [(b, a, "time") for a, b in valid_to_json]

    def convert(self, val):
        val = val[:-2]
        val = int(val)
        val = val / 1000000000.0

        if val != 0.0:
            return "%.6f" % val
        else:
            return str(val)

    def test_from_json(self):
        for i, o, type_name in self.valid_from_json:
            with self.subTest(json_val=i, py_val=o):
                self.assertEqual(self.convert(str(from_json(i, type_name))), str(o.timestamp()))


class TestIntervalSerialization(TestUtilsJSON):
    valid_to_json = [(datetime.timedelta(seconds=x), float(x)) for x in [
        0,
        -86400,
        30,
        1e-06
    ]]

    valid_from_json = [(0, "0ns", "interval"),
                       (-86400, "-86400000000000ns", "interval"),
                       (30, "30000000000ns", "interval"),
                       (0.000001, "1000ns", "interval"),
                       ]

    def test_from_json(self):
        for i, o, type_name in self.valid_from_json:
            with self.subTest(json_val=i, py_val=o):
                self.assertEqual(str(from_json(i, type_name)), o)


class TestAddrSerialization(TestUtilsJSON):
    valid_to_json = [(ipaddress.ip_address(x), x) for x in [
        "127.0.0.1",
        "0.0.0.0",
        "255.255.255.255",
        "::",
        "::1",
        "2607:feac::ddab",
    ]]

    valid_from_json = [(b, a, "addr") for a, b in valid_to_json]


class TestSubnetSerialization(TestUtilsJSON):
    valid_to_json = [(ipaddress.ip_network(x, strict=False), x) for x in [
        "127.0.0.1/32",
        "0.0.0.0/0",
        "255.255.255.0/24",
        "::/0",
        "::1/128",
        "2607::/16",
    ]]

    valid_from_json = [(b, a, "subnet") for a, b in valid_to_json]


class TestCountSerialization(TestUtilsJSON):
    valid_to_json = [(broker.Count(x), x) for x in [
        0,
        1,
        1000,
        9999999999,
    ]]

    valid_from_json = [(b, a, "count") for a, b in valid_to_json]


class TestEnumSerialization(TestUtilsJSON):
    valid_to_json = [(broker.Enum(x), x) for x in [
        "global_value",
        "eZeeKonfigurator::Option",
        "Notice::IGNORE",
    ]]

    valid_from_json = [(b, a, "enum") for a, b in valid_to_json]


class TestPortSerialization(TestUtilsJSON):
    valid_to_json = [(broker.Port(n, p), s) for n, p, s in [
        (22, broker.Port.Protocol.TCP, "22/tcp"),
        (53, broker.Port.Protocol.UDP, "53/udp"),
        (8, broker.Port.Protocol.ICMP, "8/icmp"),

        (0, broker.Port.Protocol.UDP, "0/udp"),
        (55, broker.Port.Protocol.Unknown, "55/?"),
    ]]

    valid_from_json = [(i, o, "port") for i, o in [
        ("22/tcp", broker.Port(22, broker.Port.Protocol.TCP)),
        ("53/UDP", broker.Port(53, broker.Port.Protocol.UDP)),
        ("8/icmp", broker.Port(8, broker.Port.Protocol.ICMP)),

        ("0/udp", broker.Port(0, broker.Port.Protocol.UDP)),
        ("55/unknown", broker.Port(55, broker.Port.Protocol.Unknown)),
    ]]


class TestSetSerialization(TestUtilsJSON):
    valid_to_json = [(set(x), [to_json(i) for i in x]) for x in [
        [1, 2, 3, 4],
        [0.1, 0.2, 0.3, 0.4],
        ["a", "b", "c", "d"],
        [ipaddress.ip_address("1.0.0.0"), ipaddress.ip_address("4.0.0.0"), ipaddress.ip_address("8.0.0.0")],
        [ipaddress.ip_network("::/128"), ipaddress.ip_network("2::/12", strict=False), ipaddress.ip_network("dead:beef::/128")],
        [datetime.datetime.now()],
    ]
    ]

    valid_from_json = [([to_json(i) for i in x], set(x), t) for x, t in [
        ([1, 2, 3, 4], "int"),
        ([0.1, 0.2, 0.3, 0.4], "double"),
        (["a", "b", "c", "d"], "string"),
        ([ipaddress.ip_address("1.0.0.0"), ipaddress.ip_address("4.0.0.0"), ipaddress.ip_address("8.0.0.0")], "addr"),
        ([ipaddress.ip_network("::1/128"), ipaddress.ip_network("2::/12", strict=False),
          ipaddress.ip_network("dead:beef::/128")], "subnet"),
        ([datetime.datetime.now(datetime.timezone.utc)], "time"),
    ]
    ]

    def test_to_json(self):
        for i, o in self.valid_to_json:
            with self.subTest(py_val=i, json_val=o):
                self.assertEqual(len(to_json(i)), len(o))
                self.assertEqual(sorted(to_json(i)), sorted(o))

    def test_from_json(self):
        for i, o, t in self.valid_from_json:
            with self.subTest(py_val=o, json_val=i):
                result = broker.Data.to_py(from_json(i, "set[%s]" % t))
                self.assertEqual(len(result), len(o))
                for elem in result:
                    self.assertIn(elem, o)
                for elem in o:
                    self.assertIn(elem, result)

    def test_json_function(self):
        l = [1, 2, 3, 4]
        m = models.ZeekVal.create("set[count]", l)
        self.assertEqual(l, m.json())

        l = [0.1, 0.2, 0.3, 0.4]
        m = models.ZeekVal.create("set[double]", l)
        self.assertEqual(l, m.json())

        l = ["a", "b", "c", "d"]
        m = models.ZeekVal.create("set[string]", l)
        self.assertEqual(l, m.json())


class TestVectorSerialization(TestUtilsJSON):
    valid_to_json = [(tuple(x), [to_json(i) for i in x]) for x in [
        [1, 2, 3, 4],
        [0.1, 0.2, 0.3, 0.4],
        ["a", "b", "c", "d"],
        [ipaddress.ip_address("1.0.0.0"), ipaddress.ip_address("4.0.0.0"), ipaddress.ip_address("8.0.0.0")],
        [ipaddress.ip_address("::"), ipaddress.ip_network("2::/12", strict=False), ipaddress.ip_network("dead:beef::/128")],
        [datetime.datetime.now()],
    ]
    ]

    valid_from_json = [([to_json(i) for i in x], x, t) for x, t in [
        ((1, 2, 3, 4), "int"),
        ((0.1, 0.2, 0.3, 0.4), "double"),
        (("a", "b", "c", "d"), "string"),
        ((ipaddress.ip_address("1.0.0.0"), ipaddress.ip_address("4.0.0.0"), ipaddress.ip_address("8.0.0.0")), "addr"),
        ((ipaddress.ip_network("::1/128"), ipaddress.ip_network("2::/12", strict=False),
          ipaddress.ip_network("dead:beef::/128")), "subnet"),
        ((datetime.datetime.now(datetime.timezone.utc), ), "time"),
    ]
    ]

    def test_from_json(self):
        for i, o, t in self.valid_from_json:
            with self.subTest(py_val=o, json_val=i):
                result = broker.Data.to_py(from_json(i, "vector of %s" % t))
                self.assertEqual(result, o)

    def test_json_function(self):
        l = [1, 2, 3, 4]
        m = models.ZeekVal.create("vector of count", l)
        self.assertEqual(l, m.json())

        l = [0.1, 0.2, 0.3, 0.4]
        m = models.ZeekVal.create("vector of double", l)
        self.assertEqual(l, m.json())

        l = ["a", "b", "c", "d"]
        m = models.ZeekVal.create("vector of string", l)
        self.assertEqual(l, m.json())



class TestDictSerialization(TestUtilsJSON):
    valid_to_json = [({k:v for k, v in x.items()}, to_json(x)) for x in [
        {'one': 1, 'two': 2},
        {1: 'one', 2: 'two'},
        {(1, 3): "even", (2, 4): "odd"},
    ]
    ]

    valid_from_json = [(to_json(x), x, t) for x, t in [
        ({'one': 1, 'two': 2}, "table[string] of int"),
        ({1: 'one', 2: 'two'}, "table[int] of string"),
        ({(1, 3.0): "even", (2, 4.0): "odd"}, "table[int, double] of string"),
        ({
         ("53/udp", "80/tcp"): "legit",
         ("0/tcp", "13/icmp"): "trouble"}, "table[port, port] of string")
    ]
    ]

    def test_json_function(self):
        l = {'one': 1, 'two': 2}
        m = models.ZeekContainer.create("table[string] of count", l)
        self.assertEqual({'one': 1, 'two': 2}, m.json())

        l = {('one', "22/tcp"): 1, ('two', "80/tcp"): 2}
        m = models.ZeekContainer.create("table[string, port] of count", l)
        self.assertEqual({'["one", {"port": 22, "proto": "tcp"}]': 1, '["two", {"port": 80, "proto": "tcp"}]': 2}, m.json())


    def test_from_json(self):
        for i, o, type_name in self.valid_from_json:
            with self.subTest(json_val=i, py_val=o):
                result = broker.Data.to_py(from_json(i, type_name))
                self.assertEqual(len(result), len(o))

                r_k = list(result.keys())
                o_k = list(o.keys())
                for elem in r_k:
                    self.assertIn(elem, o_k)

                r_v = result.values()
                o_v = list(o.values())
                for elem in r_v:
                    self.assertIn(elem, o_v)


class TestInvalid(TestCase):
    def test_invalid_from(self):
        with self.assertRaises(ValueError):
            to_json(self)

    def test_invalid_to(self):
        with self.assertRaises(NotImplementedError):
            from_json(self, "Test")


class TestRecordSerialization(TestCase):
    def test_vector_of_record(self):
        val = json.loads(json.dumps([["0.0.0.0/0", None, None, "Action::IGNORE"],
                         ["0.0.0.0/0", None, None, "Action::PAGE"],
                         ["0.0.0.0/0", None, "Scan::Address_Scan", "Action::Ignore"],
                         [None, "local_test", None, "Action::PAGE"],
                         [None, "local_nets", None, "Action::PAGE"],
                         [None, "neighbor_nets", None, "Action::PAGE"]]))
        type = "vector of record { src:set[subnet]; src_in:set[string]; note:set[enum]; action:set[enum]; }"

        m = models.ZeekVal.create("set[subnet]", ["0.0.0.0/0"])
        self.assertEqual(from_json(val,type), "")
