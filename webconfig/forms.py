from django.forms import modelform_factory

from webconfig import models

default_fields = ("v", "comment")

BoolForm = modelform_factory(models.ZeekBool, fields=("v",))

IntForm = modelform_factory(models.ZeekInt, fields=default_fields)
CountForm = modelform_factory(models.ZeekCount, fields=default_fields)
DoubleForm = modelform_factory(models.ZeekDouble, fields=default_fields)

TimeForm = modelform_factory(models.ZeekTime, fields=default_fields)
IntervalForm = modelform_factory(models.ZeekInterval, fields=default_fields)

StringForm = modelform_factory(models.ZeekString, fields=default_fields)

PortForm = modelform_factory(models.ZeekPort, fields=("num", "proto", "comment"))
AddrForm = modelform_factory(models.ZeekAddr, fields=default_fields)
SubnetForm = modelform_factory(models.ZeekSubnet, fields=("v", "cidr", "comment"))


EnumForm = modelform_factory(models.ZeekEnum, fields=default_fields)

#SetForm = modelform_factory(models.ZeekSet, fields=("yield_type", "comment"))


def get_form_for_model(model, post_data=None):
    if isinstance(model, models.ZeekBool):
        return BoolForm(post_data, instance=model)
    if isinstance(model, models.ZeekInt):
        return IntForm(post_data, instance=model)
    if isinstance(model, models.ZeekCount):
        return CountForm(post_data, instance=model)
    if isinstance(model, models.ZeekDouble):
        return DoubleForm(post_data, instance=model)
    if isinstance(model, models.ZeekTime):
        return TimeForm(post_data, instance=model)
    if isinstance(model, models.ZeekInterval):
        return IntervalForm(post_data, instance=model)
    if isinstance(model, models.ZeekString):
        return StringForm(post_data, instance=model)
    if isinstance(model, models.ZeekPort):
        return PortForm(post_data, instance=model)
    if isinstance(model, models.ZeekAddr):
        return AddrForm(post_data, instance=model)
    if isinstance(model, models.ZeekSubnet):
        return SubnetForm(post_data, instance=model)
    if isinstance(model, models.ZeekEnum):
        return EnumForm(post_data, instance=model)
    # if isinstance(model, models.ZeekSet):
    #     return SetForm(post_data, instance=model)

