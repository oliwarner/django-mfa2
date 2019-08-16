from django.http import JsonResponse

from .views import verify
from .models import UserKey
from . import U2F, FIDO2, totp


def has_mfa(request, username):
    if UserKey.objects.filter(username=username, enabled=1).count():
        return verify(request, username)
    return False


def has_mfa_keys(request):
    return UserKey.objects.filter(username=request.user.get_username(), enabled=1).exists()


def is_mfa(request, ignore_methods=[]):  # TODO fix! lists are mutable arguments!
    if request.session.get("mfa", {}).get("verified", False):
        if not request.session.get("mfa", {}).get("method", None) in ignore_methods:
            return True
    return False


def recheck(request):
    method = request.session.get("mfa", {}).get("method", None)
    if not method:
        return JsonResponse({"res": False})
    elif method == "U2F":
        return JsonResponse({"html": U2F.recheck(request).content})
    elif method == "FIDO2":
        return JsonResponse({"html": FIDO2.recheck(request).content})
    elif method == "TOTP":
        return JsonResponse({"html": totp.recheck(request).content})
