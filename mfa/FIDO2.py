from django.template.context_processors import csrf
from django.views.decorators.csrf import csrf_exempt
from django.http import HttpResponse, JsonResponse
from django.conf import settings
from django.utils import timezone

from fido2 import cbor
from fido2.client import ClientData
from fido2.server import Fido2Server, RelyingParty
from fido2.ctap2 import AttestationObject, AuthenticatorData
from fido2.utils import websafe_decode, websafe_encode
from fido2.ctap2 import AttestedCredentialData

from .models import UserKey
from .views import login
from .common import next_check, render


def start(request):
    return render(request, "mfa/FIDO2/add.html", {
        **csrf(request),
        'mode': 'auth',
    })


def auth(request):
    return render(request, "mfa/FIDO2/check.html", {
        **csrf(request),
        'mode': 'auth'
    })


def recheck(request):
    return render(request, "mfa/FIDO2/check.html", {
        **csrf(request),
        "mode": "recheck",
    })


def get_server():
    rp = RelyingParty(settings.FIDO_SERVER_ID, settings.FIDO_SERVER_NAME)
    return Fido2Server(rp)


def begin_registeration(request):
    server = get_server()
    registration_data, state = server.register_begin({
        'id': request.user.get_username().encode("utf8"),
        'name': (request.user.get_full_name()),
        'displayName': request.user.get_username(),
    }, get_user_credentials(request.user.get_username()))
    request.session['fido_state'] = state

    return HttpResponse(cbor.encode(registration_data), content_type='application/octet-stream')


@csrf_exempt
def complete_reg(request):
    try:
        data = cbor.decode(request.body)

        client_data = ClientData(data['clientDataJSON'])
        att_obj = AttestationObject((data['attestationObject']))
        server = get_server()
        auth_data = server.register_complete(
            request.session['fido_state'],
            client_data,
            att_obj
        )
        encoded = websafe_encode(auth_data.credential_data)
        UserKey.objects.create(
            username=request.user.get_username(),
            properties={"device": encoded, "type": att_obj.fmt},
            key_type="FIDO2",
        )
        return JsonResponse({'status': 'OK'})

    except:
        return JsonResponse({
            'status': 'ERR',
            "message": "Error on server, please try again later",
        })


def get_user_credentials(username):
    credentials = []
    for uk in UserKey.objects.filter(username=username, key_type="FIDO2"):
        credentials.append(AttestedCredentialData(websafe_decode(uk.properties["device"])))
    return credentials


def authenticate_begin(request):
    server = get_server()
    credentials = get_user_credentials(request.session.get("base_username", request.user.get_username()))
    auth_data, state = server.authenticate_begin(credentials)
    request.session['fido_state'] = state
    return HttpResponse(cbor.encode(auth_data), content_type="application/octet-stream")


@csrf_exempt
def authenticate_complete(request):
    credentials = []
    username = request.session.get("base_username", request.user.get_username())
    server = get_server()
    credentials = get_user_credentials(username)
    data = cbor.decode(request.body)
    credential_id = data['credentialId']
    client_data = ClientData(data['clientDataJSON'])
    auth_data = AuthenticatorData(data['authenticatorData'])
    signature = data['signature']

    cred = server.authenticate_complete(
        request.session.pop('fido_state'),
        credentials,
        credential_id,
        client_data,
        auth_data,
        signature
    )

    for k in UserKey.objects.filter(username=username, key_type="FIDO2", enabled=1):
        if AttestedCredentialData(websafe_decode(k.properties["device"])).credential_id == cred.credential_id:
            k.last_used = timezone.now()
            k.save()
            mfa = {"verified": True, "method": "FIDO2", 'id': k.id}
            if getattr(settings, "MFA_RECHECK", False):
                mfa["next_check"] = next_check()
            request.session["mfa"] = mfa
            res = login(request)
            return JsonResponse({'status': "OK", "redirect": res["location"]})

    return JsonResponse({'status': "err"})
