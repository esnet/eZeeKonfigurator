import datetime
from django.contrib.contenttypes.fields import GenericForeignKey, GenericRelation
from django.contrib.contenttypes.models import ContentType
from django.core.exceptions import ValidationError
from django.core.validators import validate_ipv46_address, validate_ipv4_address, RegexValidator
from django.db import models
from django.utils.timezone import make_aware
import ipaddress
import json


def get_model_for_type(type_name):
    if isinstance(type_name, list):
        return [get_model_for_type(t) for t in type_name]

    try:
        return atomic_type_mapping[type_name]
    except KeyError:
        pass

    composite = {'set[': ZeekSet,
                 'vector of ': ZeekVector,
                 'table[': ZeekTable,
                 }

    for c, m in composite.items():
        if type_name.startswith(c):
            return m

    raise ValueError("Unknown type '%s'" % type_name)


def get_index_types(type_name):
    # We special case vector to treat it as a table[count]
    if type_name.startswith("vector of "):
        return "count"

    if not ('[' in type_name and ']' in type_name):
        raise ValueError("Could not determine index type for '%s'" % type_name)

    # e.g. table[count,port] of table[foo,bar]
    return type_name.split('[')[1].split(']')[0].split(',')


def get_yield_type(type_name):
    if ' of ' not in type_name:
        return None
    return type_name.split(' of ')[1]


class Sensor(models.Model):
    """A Zeek sensor."""
    hostname = models.CharField(max_length=150)
    uuid = models.UUIDField()
    zeek_version = models.CharField(max_length=30)

    first_seen = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField(auto_now=True)
    last_ip = models.GenericIPAddressField(null=True, blank=True)

    authorized = models.BooleanField(blank=True, null=True)

    def __str__(self):
        result = "%s (%s)" % (self.hostname, self.zeek_version)
        if self.authorized:
            result += " [Authorized]"
        else:
            result += " [Unauthorized]"
        return result


class BrokerDaemon(models.Model):
    """The broker daemon communicates with our API"""
    ip = models.GenericIPAddressField("The IP address Zeek clients should connect to", null=True, blank=True)
    port = models.PositiveIntegerField("The TCP port Zeek clients should connect to", null=True, blank=True)
    uuid = models.UUIDField()

    first_seen = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField(auto_now=True)

    authorized = models.BooleanField(blank=True, null=True)

    def __str__(self):
        if not (self.ip or self.port):
            result = "<bind address not set>"
        else:
            result = "%s:%d" % (self.ip, self.port)

        if self.authorized:
            result += " [Authorized]"
        else:
            result += " [Unauthorized]"
        return result


class Option(models.Model):
    namespace = models.CharField(max_length=100, default="GLOBAL")
    name = models.CharField(max_length=100)
    datatype = models.CharField(max_length=100)
    docstring = models.CharField(max_length=1000, blank=True, null=True)
    sensor = models.ForeignKey('Sensor', on_delete=models.CASCADE)

    def __str__(self):
        if self.namespace != "GLOBAL":
            name = "%s::%s" % (self.namespace, self.name)
        else:
            name = self.name

        return name


class Setting(models.Model):
    option = models.ForeignKey('Option', on_delete=models.CASCADE)
    content_type = models.ForeignKey(ContentType, on_delete=models.CASCADE)
    object_id = models.PositiveIntegerField()
    value = GenericForeignKey()

    def __str__(self):
        return "%s = %s" % (self.option, self.value)


# Zeek data types
#################
# Shared building blocks
#
# OWS (optional whitespace)	[ \t]*
# WS  (whitespace)      	[ \t]+
# D	  (digit)               [0-9]+
# HEX                   	[0-9a-fA-F]+
# IDCOMPONENT               [A-Za-z_][A-Za-z_0-9]*
# ID	                    {IDCOMPONENT}(::{IDCOMPONENT})*
# IP6                       ("["({HEX}:){7}{HEX}"]")|("["0x{HEX}({HEX}|:)*"::"({HEX}|:)*"]")|("["({HEX}|:)*"::"({HEX}|:)*"]")|("["({HEX}|:)*"::"({HEX}|:)*({D}"."){3}{D}"]")
# FILE	                    [^ \t\n]+
# PREFIX	                [^ \t\n]+
# FLOAT	                    (({D}*"."?{D})|({D}"."?{D}*))([eE][-+]?{D})?
# H	                        [A-Za-z0-9][A-Za-z0-9\-]*
# ESCSEQ	                (\\([^\n]|[0-7]+|x[[:xdigit:]]+))
#
# #.*	/* eat comments */
# {WS}	/* eat whitespace */
#
######
# IPv6 literal constant patterns
######
#
# {IP6}	{
# 	RET_CONST(new AddrVal(extract_ip(yytext)))
# }
#
# {IP6}{OWS}"/"{OWS}{D}	{
# 	int len = 0;
# 	string ip = extract_ip_and_len(yytext, &len);
# 	RET_CONST(new SubNetVal(IPPrefix(IPAddr(ip), len, true)))
# }
#
######
# IPv4 literal constant patterns
######
#
# ({D}"."){3}{D}		RET_CONST(new AddrVal(yytext))
#
# ({D}"."){3}{D}{OWS}"/"{OWS}{D}	{
# 	int len = 0;
# 	string ip = extract_ip_and_len(yytext, &len);
# 	RET_CONST(new SubNetVal(IPPrefix(IPAddr(ip), len)))
# }


class ZeekVal(models.Model):
    """Abstract base class for Zeek values."""
    # Which setting(s) do we belong to?
    settings = GenericRelation(Setting)

    # Our value can be in a parent value for composite types.
    content_type = models.ForeignKey(ContentType, on_delete=models.CASCADE, null=True)
    object_id = models.PositiveIntegerField(null=True)
    parent = GenericForeignKey()

    @classmethod
    def create(cls, type_name, val):
        model = get_model_for_type(type_name)
        kwargs = model().parse(val)
        m = model(**kwargs)
        m.save()
        return m

    @classmethod
    def filter(cls, type_name, val):
        model = get_model_for_type(type_name)
        kwargs = model().parse(val)
        return model.objects.filter(**kwargs)

    def __str__(self):
        return str(self.v)

    def zeek_export(self):
        return str(self.v)

    class Meta:
        abstract = True


# T	RET_CONST(new Val(true, TYPE_BOOL))
# F	RET_CONST(new Val(false, TYPE_BOOL))
class ZeekBool(ZeekVal):
    """A value with Zeek 'bool' type. Valid options are 'T' or 'F'."""
    v = models.BooleanField()

    def zeek_export(self):
        if self.v:
            return "T"
        return "F"

    def parse_native_type(self, val):
        assert isinstance(val, bool), "trying to parse '%s' as bool" % type(val)
        return {"v": val}

    def parse(self, val):
        if not isinstance(val, bool):
            if val == "T" or val == "True" or val == "true":
                val = True
            elif val == "F" or val == "False" or val == "false":
                val = False
            else:
                raise ValidationError("Unknown bool value: '%s'" % val)

        return self.parse_native_type(val)


# typedef int64 bro_int_t;
class ZeekInt(ZeekVal):
    """A value with a Zeek 'int' type. Signed 64-bit int. Uses native Django support."""
    v = models.BigIntegerField()
    max_int = 9223372036854775807
    min_int = -max_int

    def parse_native_type(self, val):
        assert isinstance(val, int), "trying to parse '%s' as int" % type(val)

        if val > self.max_int:
            raise ValidationError("Value too large for an int: %d" % val)
        elif val < self.min_int:
            raise ValidationError("Value too small for an int: %d" % val)

        return {"v": val}

    def parse(self, val):
        if not isinstance(val, int):
            try:
                val = int(val)
            except ValueError as e:
                raise ValidationError(e)

        return self.parse_native_type(val)


# typedef uint64 bro_uint_t;
# {D}		{
# 		RET_CONST(val_mgr->GetCount(static_cast<bro_uint_t>(strtoull(yytext, (char**) NULL, 10))))
# 		}
class ZeekCount(ZeekVal):
    """A value with Zeek 'count' type. Unsigned 64-bit int (0 <= val <= 18,446,744,073,709,551,615 (2^64 - 1).

    This poses a problem, because Django and some DBs don't support a uint64. We store it as 2 int64's
    of most-significant and least-significant.
    """

    v_msb = models.BigIntegerField(default=0)
    v_lsb = models.BigIntegerField()
    max_int = 9223372036854775807

    def zeek_export(self):
        return str(self.v_msb + self.v_lsb)

    def __str__(self):
        return self.zeek_export()

    def parse_native_type(self, val):
        assert isinstance(val, int), "trying to parse '%s' as int" % type(val)

        if val < 0:
            raise ValidationError("Got negative value for count '%s'" % str(val))

        v_msb, v_lsb = self.convert_to_vals(val)
        return {'v_msb': v_msb, 'v_lsb': v_lsb}

    def parse(self, val):
        if not isinstance(val, int):
            try:
                val = int(val)
            except ValueError as e:
                raise ValidationError(e)

        return self.parse_native_type(val)

    def convert_to_vals(self, value):
        v_msb = 0
        if value > self.max_int:
            v_lsb = self.max_int
            v_msb = value - self.max_int
        else:
            v_lsb = value

        return (v_msb, v_lsb)

    def clean_fields(self, exclude=None):
        # We can't have negatives
        if self.v_lsb < 0 or self.v_msb < 0:
            raise ValidationError("count must be positive")

    def clean(self):
        # The data didn't get stored properly
        if self.v_msb and self.v_lsb != self.max_int:
            raise ValidationError("count must be stored as least-significant and most-significant halves")


# {FLOAT}		RET_CONST(new Val(atof(yytext), TYPE_DOUBLE))
# Uses C double behind the scenes, as does Python
class ZeekDouble(ZeekVal):
    """A value with Zeek 'double' type. Double-precision floating-point number."""
    v = models.FloatField()

    def parse_native_type(self, val):
        assert isinstance(val, float), "trying to parse '%s' as float" % type(val)

        return {'v': val}

    def parse(self, val):
        if not isinstance(val, float):
            try:
                val = float(val)
            except ValueError as e:
                raise ValidationError(e)

        return self.parse_native_type(val)


# This is a double, representing seconds since the epoch
class ZeekTime(ZeekVal):
    """A value with Zeek 'time' type."""
    v = models.DateTimeField()

    def zeek_export(self):
        return str(self.v.timestamp())

    def parse_native_type(self, val):
        assert isinstance(val, datetime.datetime), "trying to parse '%s' as datetime object" % type(val)

        return {'v': val}

    def parse(self, val):
        if not isinstance(val, datetime.datetime):
            try:
                val = make_aware(datetime.datetime.fromtimestamp(float(val)))
            except (ValueError, OverflowError) as e:
                raise ValidationError(e)

        return self.parse_native_type(val)


# {FLOAT}{OWS}day(s?)	RET_CONST(new IntervalVal(atof(yytext),Days))
# {FLOAT}{OWS}hr(s?)	RET_CONST(new IntervalVal(atof(yytext),Hours))
# {FLOAT}{OWS}min(s?)	RET_CONST(new IntervalVal(atof(yytext),Minutes))
# {FLOAT}{OWS}sec(s?)	RET_CONST(new IntervalVal(atof(yytext),Seconds))
# {FLOAT}{OWS}msec(s?)	RET_CONST(new IntervalVal(atof(yytext),Milliseconds))
# {FLOAT}{OWS}usec(s?)	RET_CONST(new IntervalVal(atof(yytext),Microseconds))
class ZeekInterval(ZeekVal):
    """A value with Zeek 'interval' type. Number of seconds, stored as a double."""
    v = models.FloatField("Number of seconds")

    def zeek_export(self):
        float_repr = "%.9f" % self.v
        float_repr = float_repr.rstrip('0')
        if float_repr[-1]  == '.':
            float_repr += "0"
        return float_repr

    def __str__(self):
        return self.zeek_export()

    def parse_native_type(self, val):
        assert isinstance(val, datetime.timedelta), "trying to parse '%s' as datetime.timedelta" % type(val)

        return {'v': val.total_seconds()}

    def parse(self, val):
        if not isinstance(val, datetime.timedelta):
            try:
                val = datetime.timedelta(seconds=float(val))
            except ValueError as e:
                raise ValidationError(e)

        return self.parse_native_type(val)


class ZeekString(ZeekVal):
    """A value with Zeek 'string' type."""
    v = models.CharField(max_length=64*1024)

    def parse_native_type(self, val):
        assert isinstance(val, str), "trying to parse '%s' as string" % type(val)

        return {'v': val}

    def parse(self, val):
        return self.parse_native_type(val)

    def zeek_export(self):
        result = ""
        # ESC_HEX  = (1 << 3),	// Not in [32, 126]? -> "\xXX"
        for c in self.v:
            if 32 > ord(c) > 126:
                result += "\\x%s" % hex(ord(c))
            else:
                result += c
        return '"%s"' % result


class ZeekPort(ZeekVal):
    """A value with Zeek 'port' type. Port number and protocol {tcp, udp, icmp}"""
    num = models.PositiveIntegerField()
    proto = models.CharField(max_length=1, choices=[('t', "tcp"), ('u', "udp"), ('i', "icmp"), ('?', "unknown")], default='?')

    def parse_native_type(self, val):
        # We don't really have a native type for this, so we'll parse a dict of {'port': 22, 'proto': 'tcp'}
        assert isinstance(val, dict), "trying to parse '%s' as dict" % type(val)

        try:
            n = val['port']
            p = val.get('proto', 'unknown')
        except (KeyError, TypeError):
            raise ValidationError("Could not parse '%s' as port." % str(val))

        if not isinstance(n, int):
            try:
                n = int(n)
            except ValueError:
                raise ValidationError("Could not parse '%s' as port." % str(val))

        if p.lower() in ['tcp', 'udp', 'icmp']:
            p = p.lower()[0]
        elif p.lower() == 'unknown':
            p = '?'
        else:
            raise ValidationError("Could not parse '%s' as port." % str(val))

        if p == 'i':
            if n < 0 or n > 255:
                raise ValidationError("ICMP port number out of range: %d" % n)
        else:
            if n < 0 or n > 65535:
                raise ValidationError("Port number out of range: %d" % n)

        return {'num': n, 'proto': p}

    def parse(self, val):
        if not isinstance(val, dict):
            data = val.split('/')
            if len(data) != 2:
                raise ValidationError("Could not parse '%s' as port." % val)
            n, p = data

            val = {'port': n, 'proto': p}

        return self.parse_native_type(val)

    def __str__(self):
        if self.proto:
            p = self.get_proto_display()
        else:
            p = "unknown"
        return "%d/%s" % (self.num, p)


    def zeek_export(self):
        return str(self)


class ZeekAddr(ZeekVal):
    """A value with Zeek 'addr' type. IPv4 of IPv6 address."""
    v = models.GenericIPAddressField()

    def parse_native_type(self, val):
        assert isinstance(val, ipaddress.IPv4Address) or isinstance(val, ipaddress.IPv6Address), "trying to parse '%s' as ipaddress" % type(val)

        return {'v': val.compressed.lower()}

    def parse(self, val):
        if not (isinstance(val, ipaddress.IPv4Address) or isinstance(val, ipaddress.IPv6Address)):
            try:
                val = ipaddress.ip_address(val)
            except ValueError:
                raise ValidationError("Could not parse '%s' as addr" % val)
        return self.parse_native_type(val)

    def __str__(self):
        return self.v.compressed.lower()


class ZeekSubnet(ZeekVal):
    """A value with Zeek 'subnet' type. IPv4 of IPv6 address and CIDR mask."""
    v = models.GenericIPAddressField()
    cidr = models.PositiveSmallIntegerField()

    def parse_native_type(self, val):
        assert isinstance(val, ipaddress.IPv4Network) or isinstance(val, ipaddress.IPv6Network), "trying to parse '%s' as ipnetwork" % type(val)

        return {'v': val.network_address.compressed.lower(), 'cidr': val.prefixlen}

    def parse(self, val):
        if not (isinstance(val, ipaddress.IPv4Network) or isinstance(val, ipaddress.IPv6Network)):
            try:
                val = ipaddress.ip_network(val, strict=False)
            except ValueError:
                raise ValidationError("Could not parse '%s' as subnet" % val)
        return self.parse_native_type(val)

    def __str__(self):
        return "%s/%d" % (self.v, self.cidr)

    def zeek_export(self):
        if ':' in self.v:
            f = "[%s]/%d"
        else:
            f = "%s/%d"
        return f % (self.v, self.cidr)


class ZeekEnum(ZeekVal):
    """A value with Zeek 'enum' type. We're just storing the string."""
    v = models.CharField(max_length=1024)

    def parse_native_type(self, val):
        assert isinstance(val, str), "trying to parse '%s' as a string" % type(val)

        data = val.split('::')
        if len(data) > 2:
            raise ValidationError("Could not parse '%s' as enum" % val)
        elif len(data) == 2:
            namespace, value = data
            RegexValidator(regex=r'^[A-Za-z_][A-Za-z_0-9]*$')(namespace)
        else:
            namespace = None
            value = data[0]
        RegexValidator(regex=r'^[A-Za-z_][A-Za-z_0-9]*$')(value)

        if namespace:
            result = "::".join([namespace, value])
        else:
            result = value

        return {'v': result}

    def parse(self, val):
        return self.parse_native_type(val)


class ZeekPattern(ZeekVal):
    """A value with Zeek 'pattern' type. A regex."""
    v = models.CharField(max_length=1024)
    is_case_insensitive = models.BooleanField(default=False)

    def parse(self, type_name, val):
        assert type_name == "pattern", "Trying to parse type '%s' as pattern." % type_name


class ZeekContainer(ZeekVal):
    """This is an abstract model for a container, such as a table, set or vector.

    A container has an index type and an optional yield type. The index type is the key, and the yield type is the value.

    There can be multiple index types.

    Indices need to be unique.

    This is a generic container type, which is reused for a few special cases:
    set[a, b, c] = table[a, b, c] of None
    vector of Z = table[count] of Z: Python list [a, b, c]
    """

    # This is mostly just a container that other values will point to, but we store some data as shortcuts
    index_types = models.CharField(max_length=1024, default="<unknown>")
    yield_type = models.CharField(max_length=1024, default="<unknown>")

    class Meta:
        abstract = True

    def _format(self, string_function):
        """The logic is very similar, so we just handle this once for either str or zeek_export."""
        result = "{"
        for table_val in ZeekTableVal.objects.filter(content_type__model="zeek%s" % self.type_name, object_id=self.pk):
            index_str = "[" + ",".join([getattr(i, string_function)() for i in table_val.get_index_vals()]) + "]"
            yield_str = getattr(table_val.v, string_function)()
            result += "%s = %s, " % (index_str, yield_str)
        result = result[:-2] + "}"
        return result

    def __str__(self):
        return self._format("__str__")

    def zeek_export(self):
        return self._format("zeek_export")

    @staticmethod
    def parse(type_name, val):
        raise NotImplementedError("Parsing a complex type from a string isn't supported.")

    def json_parse(self, type_name, json_val):
        assert type_name.startswith(self.type_name), "Trying to parse type '%s' as %s." % (type_name, self.type_name)

        index_type_list = get_index_types(type_name)
        self.index_types = ",".join(index_type_list)

        self.yield_type = get_yield_type(type_name)

        # We need to save ourselves so that we can set the ForeignKey relationships below
        self.save()

        self.json_parse_elements(index_type_list, json_val)

        return self


class ZeekTable(ZeekContainer):
    """A value with Zeek 'table' type. Associative array.    """

    # We overload this for set and vector
    type_name = 'table'

    # We expect this to be a dict
    def json_parse_elements(self, index_type_list, dict_val):
        for i, y in dict_val.items():
            yield_val = ZeekVal.create(self.yield_type, y)
            yield_val.parent = self
            yield_val.save()

            table_val = ZeekTableVal(v=yield_val, parent=self)
            table_val.save()
            for index_pos in range(len(index_type_list)):

                # This element of the index points to something, e.g. [count, port] => 2, 22/tcp.
                # First we store the value it's pointing to.
                index_elem_model = get_model_for_type(index_type_list[index_pos])
                index_elem_val = index_elem_model.create(index_type_list[index_pos], i)
                index_elem_val.save()

                # Now we store the index element itself.
                index_elem = ZeekTableIndexElement(index_pos=index_pos, y=table_val, v=index_elem_val)
                index_elem.parent = self
                index_elem.save()

    @staticmethod
    def parse(type_name, val):
        raise NotImplementedError("Parsing a complex type from a string isn't supported.")


class ZeekTableVal(ZeekVal):
    """This is one of the yield values in our table."""

    # The yield is optional, as sets inherit from this and don't yield anything.
    yield_elem_ctype = models.ForeignKey(ContentType, on_delete=models.CASCADE, related_name="yield_elem", null=True)
    yield_elem_objid = models.PositiveIntegerField(null=True)
    v = GenericForeignKey('yield_elem_ctype', 'yield_elem_objid')

    def get_index_vals(self):
        """Returns index elements that point here, sorted by index position"""
        return self.zeektableindexelement_set.order_by('index_pos')


class ZeekTableIndexElement(ZeekVal):
    """Because a table index can have multiple types (e.g. table[port, count]), we need to store our
    position in the index."""
    index_pos = models.PositiveIntegerField()

    # This points to our index value
    index_elem_ctype = models.ForeignKey(ContentType, on_delete=models.CASCADE, related_name="index_elem")
    index_elem_objid = models.PositiveIntegerField()
    v = GenericForeignKey('index_elem_ctype', 'index_elem_objid')

    # This points to our yield value
    y = models.ForeignKey('ZeekTableVal', on_delete=models.CASCADE)

    def __str__(self):
        return str(self.v)

    def zeek_export(self):
        return self.v.zeek_export()


class ZeekSet(ZeekContainer):
    """A value with Zeek 'set' type. An unordered unique list.

    This is a table[index_type] of None."""

    type_name = "set"
    yield_type = models.CharField(max_length=1024, null=True, blank=True)

    # We expect this to be a set
    def json_parse_elements(self, index_type_list, list_val):
        for i in list_val:
            table_val = ZeekTableVal(parent=self)
            table_val.save()
            for index_pos in range(len(index_type_list)):

                # This element of the index points to something, e.g. [count, port] => 2, 22/tcp.
                # First we store the value it's pointing to.
                index_elem_model = get_model_for_type(index_type_list[index_pos])
                index_elem_val = index_elem_model.create(index_type_list[index_pos], i)
                index_elem_val.save()

                # Now we store the index element itself.
                index_elem = ZeekTableIndexElement(index_pos=index_pos, y=table_val, v=index_elem_val)
                index_elem.parent = self
                index_elem.save()

    @staticmethod
    def parse(type_name, val):
        raise NotImplementedError("Parsing a complex type from a string isn't supported.")

    def _format(self, string_function):
        """The logic is very similar, so we just handle this once for either str or zeek_export."""
        result = "{"
        for table_val in ZeekTableVal.objects.filter(content_type__model="zeek%s" % self.type_name, object_id=self.pk):
            idx_vals = table_val.get_index_vals()
            if len(idx_vals) > 1:
                result += ",".join([getattr(i, string_function)() for i in idx_vals]) + ", "
            else:
                result += getattr(idx_vals[0], string_function)() + ", "

        result = result[:-2] + "}"
        return result


class ZeekVector(ZeekContainer):
    """A value with Zeek 'vector' type. table[count] of ..."""

    type_name = "vector"

    # We expect this to be a set
    def json_parse_elements(self, index_type_list, list_val):
        for i in range(len(list_val)):
            self.yield_type = "count"
            idx = ZeekVal.create("count", i)
            idx.parent = self
            idx.save()

            table_val = ZeekTableVal(v=idx, parent=self)
            table_val.save()
            for index_pos in range(len(index_type_list)):

                # This element of the index points to something, e.g. [count, port] => 2, 22/tcp.
                # First we store the value it's pointing to.
                index_elem_model = get_model_for_type(index_type_list[index_pos])
                index_elem_val = index_elem_model.create(index_type_list[index_pos], list_val[i])
                index_elem_val.save()

                # Now we store the index element itself.
                index_elem = ZeekTableIndexElement(index_pos=index_pos, y=table_val, v=index_elem_val)
                index_elem.parent = self
                index_elem.save()

    @staticmethod
    def parse(type_name, val):
        raise NotImplementedError("Parsing a complex type from a string isn't supported.")


# class ZeekVectorElement(ZeekVal):
#     """A single element within a Zeek 'vector' (index, value table)."""
#     index = models.PositiveIntegerField()
#     elem_ctype = models.ForeignKey(ContentType, on_delete=models.CASCADE, related_name="elem")
#     elem_objid = models.PositiveIntegerField()
#     v = GenericForeignKey('elem_ctype', 'elem_objid')
#
#     def __str__(self):
#         return "[%d] = %s" % (self.index, str(self.v))
#
#
# class ZeekVector(ZeekVal):
#
#     """A collection of several ZeekVectorElements"""
#     yield_type = models.CharField(max_length=100)
#
#     def parse(self, type_name, val):
#         if not type_name.startswith('vector of '):
#             raise ValidationError("Invalid type '%s' passed to vector." % type_name)
#
#         yield_type = type_name[10:]
#         if yield_type not in atomic_type_mapping:
#             print("Yield type", yield_type, "is not a valid atomic type.")
#             return None
#         self.yield_type = yield_type
#         self.save()
#
#         for i in range(len(val)):
#             model = ZeekVal.objects.create(yield_type, val[i])
#             if not model:
#                 raise ValidationError("Could not parse vector element '%s' for vector of '%s'" %(val[i], yield_type))
#             model.save()
#             elem = ZeekVectorElement(index=i, v=model, parent=self)
#             elem.save()
#
#         return self
#
#     def get_reverse(self):
#         return ZeekVectorElement.objects.filter(content_type__model="zeekvector", object_id=self.pk).order_by('index')
#
#     def __str__(self):
#         return "[%s]" % ",".join([str(x.v) for x in self.get_reverse()])
#
#     def zeek_export(self):
#         return str(self)


atomic_type_mapping = {
    'bool': ZeekBool,

    'count': ZeekCount,
    'int': ZeekInt,

    'double': ZeekDouble,
    'interval': ZeekInterval,
    'time': ZeekTime,

    'string': ZeekString,

    'enum': ZeekEnum,

    'addr': ZeekAddr,
    'port': ZeekPort,
    'subnet': ZeekSubnet,
}