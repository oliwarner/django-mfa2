from django.template.context_processors import csrf
from django.contrib.auth import get_user_model
from django.shortcuts import redirect
from django.conf import settings

from random import randint

from .models import UserKey
from .views import login
from .common import send, next_check, render


def send_email(request, username, secret):
    User = get_user_model()  # noqa
    key = getattr(User, 'USERNAME_FIELD', 'username')
    kwargs = {key: username}
    user = User.objects.get(**kwargs)
    res = render(request, "mfa/Email/mfa_email_token_template.html", {"request": request, "user": user, 'otp': secret})
    return send([user.email], "OTP", str(res.content))


def start(request):
    context = csrf(request)
    if request.method == "POST":
        if request.session["email_secret"] == request.POST["otp"]:
            UserKey.objects.create(
                username=request.user.get_username(),
                key_type="Email",
                enabled=1,
            )
            return redirect('mfa_home')
        context["invalid"] = True
    else:
        request.session["email_secret"] = str(randint(0, 100000))
        if send_email(request, request.user.get_username(), request.session["email_secret"]):
            context["sent"] = True

    return render(request, "mfa/Email/add.html", context)


def auth(request):
    context = csrf(request)
    if request.method == "POST":
        if request.session["email_secret"] == request.POST["otp"].strip():
            uk = UserKey.objects.get(username=request.session["base_username"], key_type="Email")
            mfa = {"verified": True, "method": "Email", "id": uk.id}
            if getattr(settings, "MFA_RECHECK", False):
                mfa["next_check"] = next_check()
            request.session["mfa"] = mfa

            from django.utils import timezone
            uk.last_used = timezone.now()
            uk.save()
            return login(request)
        context["invalid"] = True
    else:
        request.session["email_secret"] = str(randint(0, 100000))
        if send_email(request, request.session["base_username"], request.session["email_secret"]):
            context["sent"] = True
    return render(request, "mfa/Email/check.html", {
        **context,
        'mode': 'auth'
    })
