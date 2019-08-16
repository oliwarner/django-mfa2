from django.http import JsonResponse, HttpResponse
from django.template.context_processors import csrf
from django.conf import settings
from django.utils import timezone

import pyotp

from .models import UserKey
from .views import login
from .common import next_check, render


def verify_login(request, username, token):
    for key in UserKey.objects.filter(username=username, key_type="TOTP"):
        if pyotp.TOTP(key.properties["secret_key"]).verify(token, valid_window=30):
            key.last_used = timezone.now()
            key.save()
            return [True, key.id]
    return [False]


def recheck(request):
    context = csrf(request)
    context["mode"] = "recheck"
    if request.method == "POST":
        if verify_login(request, request.user.get_username(), token=request.POST["otp"]):
            return JsonResponse({"recheck": True})
        else:
            return JsonResponse({"recheck": False})
    return render(request, "mfa/TOTP/check.html", context)


def auth(request):
    context = csrf(request)
    if request.method == "POST":
        res = verify_login(request, request.session["base_username"], token=request.POST["otp"])
        if res[0]:
            mfa = {"verified": True, "method": "TOTP", "id": res[1]}
            if getattr(settings, "MFA_RECHECK", False):
                mfa["next_check"] = next_check()
            request.session["mfa"] = mfa
            return login(request)
        context["invalid"] = True
    return render(request, "mfa/TOTP/check.html", context)


def get_token(request):
    secret_key = pyotp.random_base32()
    totp = pyotp.TOTP(secret_key)
    request.session["new_mfa_answer"] = totp.now()
    return JsonResponse({
        "qr": pyotp.totp.TOTP(secret_key).provisioning_uri(
            str(request.user.get_username()), issuer_name=settings.TOKEN_ISSUER_NAME),
        "secret_key": secret_key
    })


def verify(request):
    answer = request.GET["answer"]
    secret_key = request.GET["key"]
    totp = pyotp.TOTP(secret_key)
    if totp.verify(answer, valid_window=60):
        uk = UserKey()
        uk.username = request.user.get_username()
        uk.properties = {"secret_key": secret_key}
        uk.key_type = "TOTP"
        uk.save()
        return HttpResponse("Success")
    return HttpResponse("Error")


def start(request):
    return render(request, "mfa/TOTP/add.html", {})
