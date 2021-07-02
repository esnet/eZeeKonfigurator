import datetime
import ipaddress
import json
import re

from django.contrib.contenttypes.fields import GenericForeignKey, \
    GenericRelation
from django.contrib.contenttypes.models import ContentType
from django.core.exceptions import ValidationError
from django.core.validators import RegexValidator
from django.db import models
from django.db.models.signals import pre_save, post_save
from django.dispatch import receiver
from django.utils.timezone import make_aware

from broker_json.utils import get_index_types, get_yield_type, get_record_types


def get_model_for_type(type_name):
    # Strip quotes
    type_name = type_name.strip('"\'')
    type_name = type_name.rstrip('"\'')

    if isinstance(type_name, list):
        return [get_model_for_type(t) for t in type_name]

    try:
        return atomic_type_mapping[type_name]
    except KeyError:
        pass

    if type_name.startswith('record {'):
        return ZeekRecord

    composite = ['set[', 'vector of ', 'table[']

    for c in composite:
        if type_name.startswith(c):
            return ZeekContainer

    raise ValueError("Unknown type '%s'" % type_name)


class SensorGroup(models.Model):
    name = models.CharField(max_length=150)
    uuid = models.UUIDField()


class Sensor(models.Model):
    """A Zeek sensor."""
    hostname = models.CharField(max_length=150)
    uuid = models.UUIDField()
    zeek_version = models.CharField(max_length=30)
    groups = models.ManyToManyField('SensorGroup')

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


class Option(models.Model):
    namespace = models.CharField(max_length=100, null=True, blank=True)
    name = models.CharField(max_length=256)
    datatype = models.CharField(max_length=512)
    docstring = models.CharField(max_length=1000, blank=True, null=True)
    sensor = models.ForeignKey('Sensor', on_delete=models.CASCADE)

    def __str__(self):
        return self.get_name()

    def get_name(self):
        if self.namespace:
            name = "%s::%s" % (self.namespace, self.name)
        else:
            name = self.name

        return name


class Change(models.Model):
    options = models.ManyToManyField(Option)
    msg = models.CharField("Summary of the change", help_text="e.g. Increased timeout due to long-lived connections", max_length=1024)
    user = models.CharField(max_length=64)
    old_val = models.CharField(max_length=1024, null=True, blank=True)
    new_val = models.CharField(max_length=1024, null=True, blank=True)
    time = models.DateTimeField(auto_created=True)

    def __str__(self):
        return "[%s] %s: %s" % (self.time, self.user, self.msg)


class Setting(models.Model):
    option = models.ForeignKey('Option', on_delete=models.CASCADE)
    content_type = models.ForeignKey(ContentType, on_delete=models.CASCADE)
    object_id = models.PositiveIntegerField()
    value = GenericForeignKey()

    def __str__(self):
        return "%s = %s" % (self.option, self.value)


class ZeekVal(models.Model):
    """Abstract base class for Zeek values."""
    # Which setting(s) do we belong to?
    settings = GenericRelation(Setting)

    comment = models.CharField("Value comment", help_text="What is this significance of the chosen value?", max_length=1024, null=True, blank=True)

    @classmethod
    def create(cls, type_name, val):
        model = get_model_for_type(type_name)
        kwargs = model().parse(type_name, val)
        m = model(**kwargs)
        m.full_clean()
        post_save.disconnect(update_container_post, sender=ZeekContainer)
        m.save()
        post_save.connect(update_container_post, sender=ZeekContainer)
        m.create_children(val)
        return m

    def create_children(self, val):
        return self

    @classmethod
    def filter(cls, type_name, val):
        model = get_model_for_type(type_name)
        kwargs = model().parse(type_name, val)
        return model.objects.filter(**kwargs)

    def __str__(self):
        return str(self.v)

    def zeek_export(self):
        return str(self.v)

    def web_str(self):
        return str(self)

    class Meta:
        abstract = True


class ZeekBool(ZeekVal):
    """A value with Zeek 'bool' type. Valid options are 'T' or 'F'."""
    v = models.BooleanField("True?")

    def zeek_export(self):
        if self.v:
            return "T"
        return "F"

    def parse_native_type(self, type_name, val):
        assert isinstance(val, bool), "trying to parse '%s' as bool" % type(val)
        return {"v": val}

    def parse(self, type_name, val):
        if not isinstance(val, bool):
            if val == "T" or val == "True" or val == "true":
                val = True
            elif val == "F" or val == "False" or val == "false":
                val = False
            else:
                raise ValidationError("Unknown bool value: '%s'" % val)

        return self.parse_native_type(type_name, val)

    def json(self):
        return self.v


class ZeekInt(ZeekVal):
    """A value with a Zeek 'int' type. Signed 64-bit int. Uses native Django support."""
    v = models.BigIntegerField("Value", )
    max_int = 9223372036854775807
    min_int = -max_int

    def parse_native_type(self, type_name, val):
        assert isinstance(val, int), "trying to parse '%s' as int" % type(val)

        if val > self.max_int:
            raise ValidationError("Value too large for an int: %d" % val)
        elif val < self.min_int:
            raise ValidationError("Value too small for an int: %d" % val)

        return {"v": val}

    def parse(self, type_name, val):
        if not isinstance(val, int):
            try:
                val = int(val)
            except ValueError as e:
                raise ValidationError(e)

        return self.parse_native_type(type_name, val)

    def clean_v(self):
        try:
            int(self.v)
        except ValueError:
            raise ValidationError("Not an integer")

    def json(self):
        return self.v


def validate_count(value):
        try:
            v = int(value)
            if v < 0:
                raise ValidationError("Counts cannot be negative")
            return
        except ValidationError as e:
            raise ValidationError("Could not parse as integer for conversion to count:", value) from e


class ZeekCount(ZeekVal):
    """A value with Zeek 'count' type. Unsigned 64-bit int (0 <= val <= 18,446,744,073,709,551,615 (2^64 - 1).

    This poses a problem, because Django and some DBs don't support a uint64. We store it as 2 int64's
    of most-significant and least-significant.
    """

    v_msb = models.BigIntegerField(default=0)
    v_lsb = models.BigIntegerField()
    v = models.CharField("value", max_length=20, validators=[validate_count])
    max_int = 9223372036854775807

    def zeek_export(self):
        return self.v

    def __str__(self):
        return self.zeek_export()

    def parse_native_type(self, type_name, val):
        assert isinstance(val, int), "trying to parse '%s' as int" % type(val)

        if val < 0:
            raise ValidationError("Got negative value for count '%s'" % str(val))

        v_msb, v_lsb, v = self.convert_to_vals(val)
        return {'v_msb': v_msb, 'v_lsb': v_lsb, 'v': v}

    def parse(self, type_name, val):
        if not isinstance(val, int):
            try:
                val = int(val)
            except ValueError as e:
                raise ValidationError(e)

        return self.parse_native_type(type_name, val)

    def convert_to_vals(self, value):
        v_msb = 0
        if value > self.max_int:
            v_lsb = self.max_int
            v_msb = value - self.max_int
        else:
            v_lsb = value

        return v_msb, v_lsb, str(v_msb + v_lsb)

    def clean_fields(self, exclude=None):
        # We can't have negatives
        if (self.v_lsb and self.v_lsb < 0) or (self.v_msb and self.v_msb < 0):
            raise ValidationError("count must be positive")

    def clean(self):
        try:
            int(self.v)
        except ValueError:
            raise ValidationError("Could not convert '%s' to an integer." % str(self.v))

        self.v_msb, self.v_lsb, self.v = self.convert_to_vals(int(self.v))
        if self.v_msb and self.v_lsb != self.max_int:
            raise ValidationError("count must be stored as least-significant and most-significant halves")

        return {'v_msb': self.v_msb, 'v_lsb': self.v_lsb, 'v': self.v}

    def json(self):
        return self.v_msb + self.v_lsb


class ZeekDouble(ZeekVal):
    """A value with Zeek 'double' type. Double-precision floating-point number."""
    v = models.FloatField("value", )

    def parse_native_type(self, type_name, val):
        assert isinstance(val, float), "trying to parse '%s' as float" % type(val)

        return {'v': val}

    def parse(self, type_name, val):
        if not isinstance(val, float):
            try:
                val = float(val)
            except ValueError as e:
                raise ValidationError(e)

        return self.parse_native_type(type_name, val)

    def json(self):
        return self.v


class ZeekTime(ZeekVal):
    """A value with Zeek 'time' type."""
    v = models.DateTimeField("value", )

    def zeek_export(self):
        return str(self.v.timestamp())

    def parse_native_type(self, type_name, val):
        assert isinstance(val, datetime.datetime), "trying to parse '%s' as datetime object" % type(val)

        return {'v': val}

    def parse(self, type_name, val):
        if not isinstance(val, datetime.datetime):
            try:
                val = make_aware(datetime.datetime.fromtimestamp(float(val)))
            except (ValueError, OverflowError) as e:
                raise ValidationError(e)

        return self.parse_native_type(type_name, val)

    def json(self):
        return self.v.timestamp()


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

    def parse_native_type(self, type_name, val):
        assert isinstance(val, datetime.timedelta), "trying to parse '%s' as datetime.timedelta" % type(val)

        return {'v': val.total_seconds()}

    def parse(self, type_name, val):
        if not isinstance(val, datetime.timedelta):
            try:
                val = datetime.timedelta(seconds=float(val))
            except ValueError as e:
                raise ValidationError(e)

        return self.parse_native_type(type_name, val)

    def json(self):
        return self.v


class ZeekString(ZeekVal):
    """A value with Zeek 'string' type."""
    v = models.CharField("value", max_length=64*1024, null=True, blank=True)

    def parse_native_type(self, type_name, val):
        assert isinstance(val, str), "trying to parse '%s' as string" % type(val)

        return {'v': val}

    def parse(self, type_name, val):
        return self.parse_native_type(type_name, val)

    def zeek_export(self):
        result = ""
        # ESC_HEX  = (1 << 3),	// Not in [32, 126]? -> "\xXX"
        for c in self.v:
            if 32 > ord(c) > 126:
                result += "\\x%s" % hex(ord(c))
            else:
                result += c
        return '"%s"' % result

    def __str__(self):
        return '%s' % self.v

    def web_str(self):
        return '"%s"' % self.v

    def json(self):
        return self.v


class ZeekPort(ZeekVal):
    """A value with Zeek 'port' type. Port number and protocol {tcp, udp, icmp}"""
    num = models.PositiveIntegerField("Port number")
    proto = models.CharField(max_length=1, choices=[('t', "tcp"), ('u', "udp"), ('i', "icmp"), ('?', "unknown")], default='?')

    def parse_native_type(self, type_name, val):
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
        elif p == "unknown":
            p = "?"
        else:
            raise ValidationError("Unknown protocol: %s" % p)

        if p == 'i':
            if n < 0 or n > 255:
                raise ValidationError("ICMP port number out of range: %d" % n)
        else:
            if n < 0 or n > 65535:
                raise ValidationError("Port number out of range: %d" % n)

        return {'num': n, 'proto': p}

    def parse(self, type_name, val):
        if not isinstance(val, dict):
            data = val.split('/')
            if len(data) != 2 or not data[1]:
                raise ValidationError("Could not parse '%s' as port." % val)
            n, p = data

            val = {'port': n, 'proto': p}

        return self.parse_native_type(type_name, val)

    def __str__(self):
        if self.proto and self.proto in ['t', 'u', 'i']:
            p = self.get_proto_display()
        else:
            # get_proto_display doesn't like '?'
            p = "?"
        return "%d/%s" % (self.num, p)

    def zeek_export(self):
        return str(self)

    def json(self):
        return str(self)


class ZeekAddr(ZeekVal):
    """A value with Zeek 'addr' type. IPv4 of IPv6 address."""
    v = models.GenericIPAddressField("IP address")

    def parse_native_type(self, type_name, val):
        assert isinstance(val, ipaddress.IPv4Address) or isinstance(val, ipaddress.IPv6Address), "trying to parse '%s' as ipaddress" % type(val)

        return {'v': val.compressed.lower()}

    def parse(self, type_name, val):
        if not (isinstance(val, ipaddress.IPv4Address) or isinstance(val, ipaddress.IPv6Address)):
            try:
                val = ipaddress.ip_address(val)
            except ValueError:
                raise ValidationError("Could not parse '%s' as addr" % val)
        return self.parse_native_type(type_name, val)

    def __str__(self):
        return str(self.v)

    def json(self):
        return self.v


class ZeekSubnet(ZeekVal):
    """A value with Zeek 'subnet' type. IPv4 of IPv6 address and CIDR mask."""
    v = models.GenericIPAddressField("Network address")
    cidr = models.PositiveSmallIntegerField("CIDR")

    field = models.CharField("Subnet in CIDR notation", max_length=64)

    def parse_native_type(self, type_name, val):
        assert isinstance(val, ipaddress.IPv4Network) or isinstance(val, ipaddress.IPv6Network), "trying to parse '%s' as ipnetwork" % type(val)

        return {'v': val.network_address.compressed.lower(), 'cidr': val.prefixlen,
                'field': "%s/%d" % (val.network_address.compressed.lower(), val.prefixlen)}

    def parse(self, type_name, val):
        if not (isinstance(val, ipaddress.IPv4Network) or isinstance(val, ipaddress.IPv6Network)):
            try:
                if ( val.startswith("'") and val.endswith("'") ) or ( val.startswith('"') and val.endswith('"') ):
                    val = val[1:-1]
                val = ipaddress.ip_network(val, strict=False)
            except ValueError:
                raise ValidationError("Could not parse '%s' as subnet" % val)
        return self.parse_native_type(type_name, val)

    def __str__(self):
        return "%s/%d" % (self.v, self.cidr)

    def json(self):
        return "%s/%d" % (self.v, self.cidr)

    def zeek_export(self):
        return self.json()

    def clean(self):
        if not self.field:
            return
        ip = ipaddress.ip_network(self.field, strict=False)
        self.v = ip.network_address.compressed.lower()
        self.cidr = int(ip.prefixlen)


class ZeekEnum(ZeekVal):
    """A value with Zeek 'enum' type. We're just storing the string."""
    v = models.CharField("value", max_length=1024)

    def parse_native_type(self, type_name, val):
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

    def parse(self, type_name, val):
        return self.parse_native_type(type_name, val)

    def json(self):
        return self.v


class ZeekRecord(ZeekVal):
    """A value with Zeek 'record' type. A value with key-value pairs, of differing yield types."""
    type_name = "record"

    field_types = models.CharField(max_length=1024)

    def parse(self, type_name, val):
        # record { arg:int; addl:int; }
        return {'field_types': type_name }

    def create_children(self, val):
        types = get_record_types(self.field_types)
        if not val or not len(val):
            return
        for i in range(len(val)):
            f = types[i]
            field = ZeekRecordField.objects.create(name=f['field_name'], val_type=f['field_type'], index_pos=i, parent=self)
            if val[i]:
                zeek_val = ZeekVal.create(f['field_type'], val[i])
                zeek_val.parent = field
                zeek_val.save()

                field.val = zeek_val
            field.save()

    def _format(self, string_function):
        """The logic is very similar, so we just handle this once for either str or zeek_export."""
        result = "["
        for record_field in self.fields.all().order_by('index_pos'):
            field_val = getattr(record_field, string_function)()
            if field_val:
                result += field_val + ", "

        if len(result) > 1:
            result = result[:-2] + "]"
        return result

    def __str__(self):
        return self._format('__str__')

    def json(self):
        result = []
        for t in get_record_types(self.field_types):
            try:
                result.append(self.fields.get(name=t['field_name']).json())
            except ZeekRecordField.DoesNotExist:
                result.append(None)
        return result


class ZeekRecordField(ZeekVal):
    """A field within a ZeekRecord."""
    name = models.CharField(max_length=1024)
    val_type = models.CharField(max_length=1024)
    docstring = models.CharField(max_length=1024, blank=True, null=True)
    index_pos = models.PositiveIntegerField()

    record_elem_ctype = models.ForeignKey(ContentType, on_delete=models.CASCADE, related_name="record_elem", null=True)
    record_elem_objid = models.PositiveIntegerField(null=True)
    val = GenericForeignKey('record_elem_ctype', 'record_elem_objid')

    parent = models.ForeignKey('ZeekRecord', help_text="The record we belong to",
                               related_name="fields", on_delete=models.CASCADE)

    def _format(self, string_function):
        if not self.val or not self.name:
            return None

        return "$" + self.name + " = " + getattr(self.val, string_function)()

    def __str__(self):
        return self._format('__str__')

    def json(self):
        if self.val:
            return self.val.json()
        return None


class ZeekContainer(ZeekVal):
    """This is an abstract model for a container, such as a table, set or vector.

    A container has an index type and an optional yield type. The index type is the key, and the yield type is the value.

    There can be multiple index types.

    Indices need to be unique.

    This is a generic container type, which is reused for a few special cases:
    set[a, b, c] = table[a, b, c] of None
    vector of Z = table[count] of Z: Python list [a, b, c]
    """

    ctr_type = models.CharField(max_length=1, choices=[('s', "set"), ('v', "vector"), ('t', "table"), ('p', "pattern")])

    v = models.CharField("Current value", max_length=1024, null=True, blank=True)

    type_name = models.CharField("How Zeek identifies the name, e.g. table[count, port] of string", max_length=512)

    # This is mostly just a container that other values will point to, but we store some data as shortcuts
    index_types = models.CharField(max_length=1024, default="<unknown>", null=True, blank=True)
    yield_type = models.CharField(max_length=1024, default="<unknown>", null=True, blank=True)

    def parse(self, type_name, val):
        return {'ctr_type': type_name[0].lower(),
                'type_name': type_name,
                'index_types': str(get_index_types(type_name)),
                'yield_type': get_yield_type(type_name),
                'v': str(val)[:1024]}

    def create_children(self, vals):
        # Depending on the datatype, we expect:
        #
        #  set: a list. If it's a multi-key set, a list of lists.

        if self.ctr_type == 's':
            assert isinstance(vals, list), "trying to parse '%s' as a list (%s)" % (type(vals), self.get_ctr_type_display())

            for val in vals:
                if not isinstance(val, list):
                    val = [val]

                self.create_child(val)

        #  vector: a list of single values
        elif self.ctr_type == 'v':
            assert isinstance(vals, list), "trying to parse '%s' as a list (%s)" % (type(vals), self.get_ctr_type_display())

            position = 0
            for val in vals:
                self.create_child(val, position)
                position += 1

        #  table: a dict of k/v pairs
        elif self.ctr_type == 't':
            assert isinstance(vals, dict), "trying to parse '%s' as a dict (%s)" % (type(vals), self.get_ctr_type_display())

            for k, v in vals.items():
                if not isinstance(k, list) and not isinstance(k, tuple):
                    k = [k]

                self.create_child(k, v)

        else:
            raise NotImplementedError

        self.v = ""
        self.save()

    def create_child(self, idx_vals, key_val=None):
        index_types = get_index_types(self.index_types)
        index_offset = 0

        # First, we create our item
        if self.ctr_type == 'v':
            item = ZeekContainerItem(parent=self, v=ZeekVal.create(self.yield_type, idx_vals), position=key_val)
            item.save()
            return
        elif self.ctr_type == 's':
            item = ZeekContainerItem(parent=self)
            item.save()
        elif self.ctr_type == 't':
            item = ZeekContainerItem(parent=self, v=ZeekVal.create(self.yield_type, key_val))
            item.save()

        # Now we create all the keys

        if not isinstance(idx_vals, list) and not isinstance(idx_vals, tuple):
            idx_vals = list([idx_vals])

        for c, t in zip(idx_vals, index_types):
            if not t:
                continue
            key_value = ZeekVal.create(t, c)

            key = ZeekContainerKey(parent=item, index_offset=index_offset, v=key_value)
            key.save()
            index_offset += 1

    def __str__(self, limit=10, offset=0):
        fmt = {'s': "{%s}", 't': "{%s}",
               'v': "[%s]"}

        separator = {'s': ", ",
                     't': ", ",
                     'v': ", ",
                     }

        count = self.items.all().count()

        if self.ctr_type == 's' or self.ctr_type == 't':
            data = [str(i) for i in self.items.all()[offset:offset+limit]]
        elif self.ctr_type == 'v':
            data = [str(i.v) for i in self.items.all().order_by('position')[offset:offset+limit]]
        else:
            data = ["UNKNOWN: '%s'" % self.type_name]

        if count > offset + limit:
            data.append("...and %d more elements..." % (count - limit - offset))

        return fmt.get(self.ctr_type, '[%s] WARNING TYPE NOT SET') % separator.get(self.ctr_type, " # ").join(data)

    def clean_type_name(self):
        if not self.type_name:
            raise ValidationError("Type name is not set")

    def json(self):
        # A set is a list
        if self.ctr_type == 's':
            return [i.json() for i in self.items.all()]
        # And so is a vector
        elif self.ctr_type == 'v':
            return [i.v.json() for i in self.items.all()]
        # A set is a dict
        elif self.ctr_type == 't':
            result = {}
            for i in self.items.all():
                key_val = i.json()
                if len(get_index_types(self.index_types)) > 1:
                    key_val = json.dumps(key_val)
                result[key_val] = i.v.json()
            return result


@receiver(pre_save, sender=ZeekContainer)
def update_container_pre(sender, instance, **kwargs):
    # This updates our type name(s)
    instance.ctr_type = instance.type_name[0]
    instance.index_types = str(get_index_types(instance.type_name))
    instance.yield_type = get_yield_type(instance.type_name)


def parse_string_composite(string):
    data = string.split('\n')
    if len(data) == 1:
        data = string.split(',')

    vals = []
    for s in data:
        s = s.strip()
        if (s.startswith('"') and s.endswith('"')) or (s.startswith("'") and s.endswith("'")):
            s = s[1:-1]
        vals.append(s)

    return vals


@receiver(post_save, sender=ZeekContainer)
def update_container_post(sender, instance, **kwargs):
    if not instance.v:
        instance.v = ""

    idx_types = get_index_types(instance.index_types)
    str_val = instance.v.strip('[').rstrip(']')

    # We build k:v pairs, depending on the type of container

    items = []

    # First up, a vector. We track the index via position.
    if str_val and instance.ctr_type == 'v':
        if instance.yield_type != 'string':
            data = str_val.split(',')
        else:
            data = parse_string_composite(str_val)

        for i in range(len(data)):
            existing = instance.items.filter(position=i)
            if len(existing) == 1:
                if data[i] and data[i] != str(existing[0]):
                    existing[0].delete()
                else:
                    continue

            instance.create_child(data[i], i)

        return

    # Next is a set
    if str_val and len(idx_types):
        for i in idx_types:
            # We expect comma-delimited values
            if i != 'string':
                # Strings can have embedded commas, so we'll deal with them separately.
                vals = [x.strip() for x in str_val.split(',')]
            else:
                vals = parse_string_composite(str_val)

            for existing in instance.items.all():
                if str(existing) not in vals:
                    existing.delete()
            existing_vals = [str(x) for x in instance.items.all()]
            for v in vals:
                if v and v not in existing_vals:
                    instance.create_child(v)
                    existing_vals.append(v)


class ZeekContainerItem(ZeekVal):
    """This is a single item in the container. It can be thought of as a key-value pair in a Python dict."""

    parent = models.ForeignKey('ZeekContainer', help_text="The container value that we belong to",
                               related_name="items", on_delete=models.CASCADE)

    # We'll have a reverse relationship of keys

    # This is our yield value. It's optional (e.g. sets).
    content_type = models.ForeignKey(ContentType, on_delete=models.SET_NULL, null=True, blank=True)
    object_id = models.PositiveIntegerField(null=True, blank=True)
    v = GenericForeignKey()

    position = models.PositiveIntegerField("Position in the container, for those where order matters", null=True, blank=True)

    def __str__(self):
        keys = self.keys.all()
        result = ", ".join([str(k) for k in keys])
        if not result:
            return str(self.v)

        if len(keys) > 1 or self.v:
            result = "[%s]" % result
        if self.v:
            result += " = %s" % str(self.v)

        return result

    def json(self):
        keys = self.keys.all()
        if len(keys) > 1:
            return tuple([x.json() for x in keys])
        elif len(keys) == 1:
            return keys[0].json()
        else:
            return self.v.json()


class ZeekContainerKey(ZeekVal):
    """Because a container can have multiple keys for a single item, we store each one separately."""
    parent = models.ForeignKey('ZeekContainerItem', help_text="The key-value pair that we belong to",
                               related_name="keys", on_delete=models.CASCADE)

    index_offset = models.PositiveSmallIntegerField("For composite keys, the 0-index position that we're in.")

    # This is our actual value. It is NOT optional.
    content_type = models.ForeignKey(ContentType, on_delete=models.CASCADE)
    object_id = models.PositiveIntegerField()
    v = GenericForeignKey()

    def json(self):
        return self.v.json()


class ZeekPattern(ZeekContainer):
    """A value with Zeek 'pattern' type. A regex."""
    # This is a list of patterns OR-ed together. Patterns point here.

    exact_format = "^?(%s)$?"
    anywhere_format = "^?(.|\\n)*(%s)"

    add_exact_format = "(%s)|(^?(%s)$?)"
    add_anywhere_format = "(%s)|(^?(.|\\n)*(%s))"

    def parse_native_type(self, type_name, val):
        return {'yield_type': 'pattern', 'ctr_type': 'p', 'type_name': 'pattern'}

    def create_children(self, val):
        exact, anywhere = val
        i = 0
        for part in self.get_exact_parts(exact):
            p = ZeekPattern(yield_type='pattern', v=part, ctr_type='p', type_name='pattern')
            p.save()
            e = ZeekContainerItem(v=p, position=i, parent=self)
            e.save()
            i += 1

    def parse(self, type_name, val):
        return self.parse_native_type(type_name, val)

    def __str__(self, limit=10, offset=0):
        self.json()
        if self.items.all()[offset:offset+limit]:
            count = self.items.all().count()
            result = " | ".join(str(p.v) for p in self.items.all()[offset:offset+limit])

            if count > offset + limit:
                result += "...OR %d more patterns..." % (count - limit - offset)
            return result

        result = self.v
        return "/%s/" % result

    def zeek_export(self):
        return str(self)

    def strip_wrappers(self, val):
        if val.startswith("^?(") and val.endswith(")$?"):
            return val[3:-3]
        elif val.startswith("(^?(") and val.endswith(")$?)"):
            return val[4:-4]

        raise ValidationError("Wrappers not found")

    def get_last_elem_exact(self, val):
        # Example: ^?(foo)$?)|(^?(bar)$?
        m = re.search(r'\)+\$\?\)\|\(\^\?\((.*)\)\$\?\)$', val)
        result = m.group(1)
        # Our search is greedy, so we keep going until we're done
        while ")$?)|(^?(" in result:
            m = re.search(r'\)+\$\?\)\|\(\^\?\((.*)$', result)
            result = m.group(1)

        return result

    def get_exact_parts(self, val):
        # When Zeek appends to an existing pattern, it does:
        # "(%s)|(^?(%s)$?)" % old, new

        if not val.startswith("^?(") or not val.endswith(")$?"):
            raise ValidationError("Could not parse '%s' as two exact parts" % val)

        val = self.strip_wrappers(val)

        parts = []

        while ")$?)|(^?(" in val:
            last_elem = self.get_last_elem_exact(val)
            parts.insert(0, last_elem)
            # We remove |(^?(%s)$?) % last_elem
            val = val.replace("|(^?(%s)$?)" % last_elem, "")
            val = self.strip_wrappers(val)

        parts.insert(0, val)
        return parts

    def json(self):
        exact = anywhere = ""

        if not self.items.all():
            return [self.exact_format % self.v, self.anywhere_format % self.v]

        for i in self.items.all().order_by('position'):
            if exact:
                exact = self.add_exact_format % (exact, i.v)
            else:
                exact = self.exact_format % i.v

            if anywhere:
                anywhere = self.add_anywhere_format % (anywhere, i.v)
            else:
                anywhere = self.anywhere_format % i.v
        
        return [exact, anywhere]


atomic_type_mapping = {
    'bool': ZeekBool,

    'count': ZeekCount,
    'int': ZeekInt,

    'double': ZeekDouble,
    'interval': ZeekInterval,
    'time': ZeekTime,

    'pattern': ZeekPattern,
    'string': ZeekString,

    'enum': ZeekEnum,

    'addr': ZeekAddr,
    'port': ZeekPort,
    'subnet': ZeekSubnet,
}


def get_name_of_model(model):
    for k, v in atomic_type_mapping.items():
        if isinstance(model, v) or model is v:
            return k

    return model._meta.model_name


def get_doc_types(model):
    for k, v in atomic_type_mapping.items():
        if isinstance(model, v) or model is v:
            return [k]

    if isinstance(model, ZeekPattern) or model is ZeekPattern:
        return ["pattern"]

    types = []

    if isinstance(model, ZeekContainer) or model is ZeekContainer:
        types = [model.type_name.split(' ')[0].split('[')[0]]

    return types