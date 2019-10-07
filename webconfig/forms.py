from django.forms import modelform_factory, modelformset_factory

from webconfig import models

default_fields = ("v",)


def get_factory(model, function=modelform_factory):
    if isinstance(model, models.ZeekBool) or model is models.ZeekBool:
        return function(models.ZeekBool, fields=("v",))

    elif isinstance(model, models.ZeekInt) or model is models.ZeekInt:
        return function(models.ZeekInt, fields=default_fields)
    elif isinstance(model, models.ZeekCount) or model is models.ZeekCount:
        return function(models.ZeekCount, fields=default_fields)
    elif isinstance(model, models.ZeekDouble) or model is models.ZeekDouble:
        return function(models.ZeekDouble, fields=default_fields)

    elif isinstance(model, models.ZeekTime) or model is models.ZeekTime:
        return function(models.ZeekTime, fields=default_fields)
    elif isinstance(model, models.ZeekInterval) or model is models.ZeekInterval:
        return function(models.ZeekInterval, fields=default_fields)

    elif isinstance(model, models.ZeekString) or model is models.ZeekString:
        return function(models.ZeekString, fields=default_fields)

    elif isinstance(model, models.ZeekPort) or model is models.ZeekPort:
        return function(models.ZeekPort, fields=("num", "proto", "comment"))
    elif isinstance(model, models.ZeekAddr) or model is models.ZeekAddr:
        return function(models.ZeekAddr, fields=default_fields)
    elif isinstance(model, models.ZeekSubnet) or model is models.ZeekSubnet:
        return function(models.ZeekSubnet, fields=("field", "comment"))

    elif isinstance(model, models.ZeekEnum) or model is models.ZeekEnum:
        return function(models.ZeekEnum, fields=default_fields)

    elif isinstance(model, models.ZeekPattern) or model is models.ZeekPattern:
        return function(models.ZeekPattern, fields=default_fields)

    raise ValueError("Unknown model type %s" % models.get_name_of_model(model))


def get_form_for_model(model, post_data=None, required=True):
    prefix = str(type(model)) + str(model.pk)
    factory = get_factory(model)
    return factory(post_data, instance=model, prefix=prefix, use_required_attribute=required)


def get_empty_form(model, post_data=None, prefix="", required=True):
    prefix = models.get_name_of_model(model) + prefix
    factory = get_factory(model, modelform_factory)
    return factory(post_data, prefix=prefix, use_required_attribute=required)

