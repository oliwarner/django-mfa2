from django.shortcuts import redirect
from django.http import HttpResponse
from django.conf import settings
from user_agents import parse
from django.utils.module_loading import import_string

from .models import UserKey
from .common import render


def index(request):
    context = {
        "keys": [],
        "UNALLOWED_AUTHEN_METHODS": settings.MFA_UNALLOWED_METHODS,
        "HIDE_DISABLE": getattr(settings, "MFA_HIDE_DISABLE", [])
    }

    for k in UserKey.objects.filter(username=request.user.get_username()):
        if k.key_type == "Trusted Device":
            k.device = parse(k.properties.get("user_agent", "-----"))
        elif k.key_type == "FIDO2":
            k.device = k.properties.get("type", "----")
        context["keys"].append(k)

    return render(request, "mfa/home.html", context)


def verify(request, username):
    request.session["base_username"] = username
    keys = UserKey.objects.filter(username=username, enabled=1)
    methods = list(set([k.key_type for k in keys]))

    request.session["mfa_methods"] = methods
    if len(methods) == 1:
        return redirect(methods[0].lower() + "_auth")

    return show_methods(request)


def show_methods(request):
    username = request.user.get_username()
    request.session["base_username"] = request.user.get_username()
    keys = UserKey.objects.filter(username=username, enabled=1)
    methods = list(set([k.key_type for k in keys]))

    request.session["mfa_methods"] = methods
    if len(methods) == 1:
        return redirect(methods[0].lower() + "_auth")

    return render(request, "mfa/select_mfa_method.html", {})


def reset_cookie(request):
    del request.session['mfa']
    response = redirect(settings.LOGIN_URL)
    response.delete_cookie("base_username")
    return response


def login(request):
    request.session['mfa-verified'] = True

    if 'mfa-next' in request.session:
        return redirect(request.session['mfa-next'])

    callback = getattr(settings, 'MFA_LOGIN_CALLBACK', False)
    if callback:
        callable_func = import_string(settings.MFA_LOGIN_CALLBACK)
        return callable_func(request, username=request.session["base_username"])

    return redirect(settings.LOGIN_URL)


def del_key(request):
    key = UserKey.objects.get(id=request.GET["id"])
    if key.username == request.user.get_username():
        key.delete()
        return HttpResponse("Deleted Successfully")
    else:
        return HttpResponse("Error: You own this token so you can't delete it")


def toggle_key(request):
    key_id = request.GET["id"]
    q = UserKey.objects.filter(username=request.user.get_username(), id=key_id)

    if q.count() == 1:
        key = q[0]
        key.enabled = not key.enabled
        key.save()
        return HttpResponse("OK")
    else:
        return HttpResponse("Error")


def goto(request, method):
    return redirect(method.lower() + "_auth")
