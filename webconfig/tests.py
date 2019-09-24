from django.core.exceptions import ValidationError
from django.test import TestCase
from webconfig import models


class ZeekValTestCase(TestCase):
    model = None
    type_name = ""

    invalid_types = ["addr", "any", "bool", "count", "double", "enum", "int", "interval", "pattern",
                     "port", "record", "set", "string", "subnet", "table", "time", "vector", "",
                     "integer", "uint", "uint16", "void", "float"]

    valid_pairs = []
    invalid_input = []

    def setUp(self):
        if self.type_name in self.invalid_types:
            self.invalid_types.remove(self.type_name)

    def test_import_export(self):
        if not self.model:
            return
        for import_val, export_val in self.valid_pairs:
            with self.subTest(import_val=import_val, export_val=export_val):
                m = self.model.create(self.type_name, import_val)
                m.save()
                self.assertEqual(m.zeek_export(), export_val)

    def test_invalid_type(self):
        if not self.model:
            return
        for t in self.invalid_types:
            with self.subTest(type_name=t):
                with self.assertRaises(AssertionError):
                    self.model.create(t, self.valid_pairs[0][0])

    def test_invalid_input(self):
        if not self.model:
            return
        for i in self.invalid_input:
            with self.subTest(import_val=i):
                with self.assertRaises(ValidationError):
                    self.model.create(self.type_name, i)


class ZeekBoolTestCase(ZeekValTestCase):
    type_name = "bool"
    model = models.ZeekBool

    valid_pairs = [
        ("True", "T"),
        ("False", "F"),
    ]

    invalid_input = [
        "T", "F", "t", "f", "true", "false",
        "1", "0", "1 == 1", "OR True",
        "Tru", "Falsee", ""
    ]

            
class ZeekIntTestCase(ZeekValTestCase):
    type_name = "int"
    model = models.ZeekInt

    valid_pairs = [
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


class ZeekCountTestCase(ZeekValTestCase):
    type_name = "count"
    model = models.ZeekCount

    valid_pairs = [
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


class ZeekDoubleTestCase(ZeekValTestCase):
    type_name = "double"
    model = models.ZeekDouble

    valid_pairs = [
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


class ZeekTimeTestCase(ZeekValTestCase):
    type_name = "time"
    model = models.ZeekTime

    valid_pairs = [
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


class ZeekIntervalTestCase(ZeekValTestCase):
    type_name = "interval"
    model = models.ZeekInterval

    valid_pairs = [
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


class ZeekStringTestCase(ZeekValTestCase):
    type_name = "string"
    model = models.ZeekString

    valid_pairs = [
        ("", ""),
        ("abc", "abc"),
        ("'abc'", "'abc'"),
        ("'abc", "'abc"),
        ('"abc', '"abc'),

        # String escaping
        (r"a\x09y", "a\\x09y"),
        (r"a\x0d\x0a\x08b", "a\\x0d\\x0a\\x08b"),
        (r"foo\x00bar", "foo\\x00bar")
    ]


