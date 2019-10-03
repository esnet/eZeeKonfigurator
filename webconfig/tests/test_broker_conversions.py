from django.test import TestCase

from eZeeKonfigurator.standalone_scripts.utils import *


class TestUtilsJSON(TestCase):
    valid_to_json = valid_from_json = []

    def test_to_json(self):
        for i, o in self.valid_to_json:
            with self.subTest(py_val=i, json_val=o):
                self.assertEqual(to_json(i), o)

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
        b"abc",
        b"\u0000",
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
        ({'port': 22, 'proto': "tcp"}, broker.Port(22, broker.Port.Protocol.TCP)),
        ({'port': 53, 'proto': "UDP"}, broker.Port(53, broker.Port.Protocol.UDP)),
        ({'port': 8, 'proto': "icmp"}, broker.Port(8, broker.Port.Protocol.ICMP)),

        ({'port': 0, 'proto': "udp"}, broker.Port(0, broker.Port.Protocol.UDP)),
        ({'port': 55, 'proto': "unknown"}, broker.Port(55, broker.Port.Protocol.Unknown)),
    ]]


class TestSetSerialization(TestUtilsJSON):
    valid_to_json = [(set(x), [to_json(i) for i in x]) for x in [
        [1, 2, 3, 4],
        [0.1, 0.2, 0.3, 0.4],
        ["a", "b", "c", "d"],
        [ipaddress.ip_address("1.0.0.0"), ipaddress.ip_address("4.0.0.0"), ipaddress.ip_address("8.0.0.0")],
        [ipaddress.ip_address("::"), ipaddress.ip_network("2::/12", strict=False), ipaddress.ip_network("dead:beef::/128")],
        [datetime.datetime.now()],
    ]
    ]

    def test_to_json(self):
        for i, o in self.valid_to_json:
            with self.subTest(py_val=i, json_val=o):
                self.assertEqual(len(to_json(i)), len(o))
                self.assertEqual(sorted(to_json(i)), sorted(o))


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


class TestDictSerialization(TestUtilsJSON):
    valid_to_json = [({k:v for k, v in x.items()}, to_json(x)) for x in [
        {'one': 1, 'two': 2},
        {1: 'one', 2: 'two'},
        {(1, 3): "even", (2, 4): "odd"},
    ]
    ]

