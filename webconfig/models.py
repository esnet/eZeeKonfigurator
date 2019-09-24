import datetime
from django.contrib.contenttypes.fields import GenericForeignKey
from django.contrib.contenttypes.models import ContentType
from django.core.exceptions import ValidationError
from django.db import models


class Sensor(models.Model):
    """Zeek sensor"""
    hostname = models.CharField(max_length=150)
    uuid = models.UUIDField()
    zeek_version = models.CharField(max_length=30)

    first_seen = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField(auto_now=True)
    last_ip = models.GenericIPAddressField()

    authorized = models.BooleanField(blank=True, null=True)

    def __str__(self):
        return "%s (%s)" % (self.hostname, self.zeek_version)


class Option(models.Model):
    namespace = models.CharField(max_length=100, default="GLOBAL")
    name = models.CharField(max_length=100)
    datatype = models.CharField(max_length=100)
    docstring = models.CharField(max_length=1000)
    sensor = models.ForeignKey('Sensor', on_delete=models.CASCADE)


class Setting(models.Model):
    option = models.ForeignKey('Option', on_delete=models.CASCADE)
    content_type = models.ForeignKey(ContentType, on_delete=models.CASCADE)
    object_id = models.PositiveIntegerField()
    value = GenericForeignKey()


def parse_atomic(type_name, value):
    model = atomic_type_mapping.get(type_name, None)

    if not model:
        return None

    return model.create(type_name, value)

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
    # Our value can be in a parent value for composite types.
    content_type = models.ForeignKey(ContentType, on_delete=models.CASCADE, null=True)
    object_id = models.PositiveIntegerField(null=True)
    parent = GenericForeignKey()

    def __str__(self):
        return str(self.v)

    def zeek_export(self):
        return str(self.v)

    @classmethod
    def create(cls, type_name, json_val):
        z = cls()
        return z.parse(type_name, json_val)

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

    def parse(self, type_name, json_val):
        self.v = json_val == "True"
        return self


# typedef int64 bro_int_t;
class ZeekInt(ZeekVal):
    """A value with a Zeek 'int' type. Signed 64-bit int. Uses native Django support."""
    v = models.BigIntegerField()

    def parse(self, type_name, json_val):
        self.v = int(json_val)
        return self


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

    def parse(self, type_name, json_val):
        i = int(json_val)

        if i > self.max_int:
            self.v_lsb = self.max_int
            self.v_msb = i - self.max_int
        else:
            self.v_lsb = i

        return self

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

    def parse(self, type_name, json_val):
        self.v = float(json_val)
        return self


# This is a double, representing seconds since the epoch
class ZeekTime(ZeekVal):
    """A value with Zeek 'time' type."""
    v = models.DateTimeField()

    def zeek_export(self):
        return self.v.timestamp()

    def parse(self, type_name, json_val):
        self.v = datetime.datetime.fromtimestamp(json_val)
        return self


# {FLOAT}{OWS}day(s?)	RET_CONST(new IntervalVal(atof(yytext),Days))
# {FLOAT}{OWS}hr(s?)	RET_CONST(new IntervalVal(atof(yytext),Hours))
# {FLOAT}{OWS}min(s?)	RET_CONST(new IntervalVal(atof(yytext),Minutes))
# {FLOAT}{OWS}sec(s?)	RET_CONST(new IntervalVal(atof(yytext),Seconds))
# {FLOAT}{OWS}msec(s?)	RET_CONST(new IntervalVal(atof(yytext),Milliseconds))
# {FLOAT}{OWS}usec(s?)	RET_CONST(new IntervalVal(atof(yytext),Microseconds))
class ZeekInterval(ZeekVal):
    """A value with Zeek 'interval' type. Number of seconds, stored as a double.

    We actually deviate from the Zeek format a bit here, for brevity.

    Zeek: 2.0 hrs 12.0 mins
    Us: 2 hrs 12 mins
    """
    v = models.FloatField("Number of seconds")
    units = [('day', 24*60*60.0), ('hr', 60*60.0), ('min', 60.0), ('sec', 1.0), ('msec', 1.0/1000), ('usec', 1.0/1000/1000)]

    def zeek_export(self):
        # # Iterate through the units, from biggest to smallest. We skip the last one, since that's our fall-back.
        # for name, size in self.units[:-1]:
        #     if self.v >= size or self.v <= -size:
        #         num = self.v / size
        #         break
        # else:
        #     # If we're still here, we return the smallest unit
        #     name, size = self.units[-1]
        #     num = self.v / size
        #
        # if num != 1.0:
        #     plural = "s"
        # else:
        #     plural = ""
        #
        # num_str = ("%f" % num).rstrip('0').rstrip('.')
        # return "%s %s%s" % (num_str, name, plural)
        return str(self.v)

    def __str__(self):
        return self.zeek_export()

    def parse(self, type_name, json_val):
        # We're parsing something like "5.0 days 5.0 hrs 5.0 mins 5.0 secs 5.0 msecs 4.0 usecs"
        num = 0.0
        data = json_val.split(' ')
        for name, size in self.units:
            if data[1] == name or data[1] == (name + "s"):
                num += float(data[0]) * size
                # Pop the first two elements off
                data.pop(0)
                data.pop(0)
                if not data:
                    break
        else:
            raise ValidationError("Could not parse '%s' as an interval" % json_val)

        self.v = num
        return self


class ZeekString(ZeekVal):
    """A value with Zeek 'string' type."""
    v = models.CharField(max_length=64*1024)

    def parse(self, type_name, json_val):
        self.v = json_val
        return self

    def zeek_export(self):
        return '"%s"' % self.v


class ZeekEnum(ZeekVal):
    """A value with Zeek 'enum' type. We're just storing the string."""
    v = models.CharField(max_length=1024)

    def parse(self, type_name, json_val):
        self.v = json_val
        return self


class ZeekSet(ZeekVal):
    """A value with Zeek 'set' type. An ordered list."""
    # We have things point here, so all we need to store is the Zeek description of our index type.
    index_type = models.CharField(max_length=100)

    def parse(self, type_name, json_val):
        if not type_name.startswith('set['):
            raise ValidationError("Invalid type '%s' passed to set." % type_name)

        index_type = type_name[4:].split(']', 1)[0]

        if index_type not in atomic_type_mapping:
            print("Index type", index_type, "is not a valid atomic type.")
            return None
        self.index_type = index_type
        self.save()
        self.get_reverse().delete()
        for i in json_val:
            model = parse_atomic(index_type, i)
            if not model:
                continue
            model.parent = self
            model.save()

        return self

    @classmethod
    def create(cls, type_name, json_val):
        z = cls()
        return z.parse(type_name, json_val)

    def __str__(self):
        if self.index_type not in atomic_type_mapping:
            return "Broken"
        if not self.get_reverse():
            return "[]"
        return "\n".join(str(x) for x in self.get_reverse())

    def get_reverse(self):
        return atomic_type_mapping[self.index_type].objects.filter(content_type__model="zeekset", object_id=self.pk)

    def zeek_export(self):
        if not self.get_reverse():
            return "{}"
        return "{" + ", ".join(str(x) for x in self.get_reverse()) + "}"


atomic_type_mapping = {
    'bool': ZeekBool,

    'count': ZeekCount,
    'int': ZeekInt,

    'double': ZeekDouble,
    'interval': ZeekInterval,
    'time': ZeekTime,

    'string': ZeekString,

    'enum': ZeekEnum,
}
