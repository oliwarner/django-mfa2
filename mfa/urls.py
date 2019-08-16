from django.urls import path
from . import views, totp, U2F, helpers, FIDO2, Email


urlpatterns = [
    path('', views.index, name="mfa_home"),

    path('totp/start/', totp.start, name="start_new_otop"),
    path('totp/get-token/', totp.get_token, name="get_new_otop"),
    path('totp/verify/', totp.verify, name="verify_otop"),
    path('totp/auth/', totp.auth, name="totp_auth"),
    path('totp/recheck/', totp.recheck, name="totp_recheck"),

    path('email/start/', Email.start, name="start_email"),
    path('email/auth/', Email.auth, name="email_auth"),

    path('u2f/', U2F.start, name="start_u2f"),
    path('u2f/bind/', U2F.bind, name="bind_u2f"),
    path('u2f/auth/', U2F.auth, name="u2f_auth"),
    path('u2f/process-recheck/', U2F.process_recheck, name="u2f_recheck"),
    path('u2f/verify/', U2F.verify, name="u2f_verify"),

    path('fido2/', FIDO2.start, name="start_fido2"),
    path('fido2/auth/', FIDO2.auth, name="fido2_auth"),
    path('fido2/begin-auth/', FIDO2.authenticate_begin, name="fido2_begin_auth"),
    path('fido2/complete-auth/', FIDO2.authenticate_complete, name="fido2_complete_auth"),
    path('fido2/begin-reg/', FIDO2.begin_registeration, name="fido2_begin_reg"),
    path('fido2/complete-reg/', FIDO2.complete_reg, name="fido2_complete_reg"),

    path('goto/<str:method>/', views.goto, name="mfa_goto"),
    path('authenticate/', views.show_methods, name="mfa_methods_list"),
    path('recheck/', helpers.recheck, name="mfa_recheck"),
    path('toggle-key/', views.toggle_key, name="toggle_key"),
    path('delete/', views.del_key, name="mfa_del_key"),
    path('reset/', views.reset_cookie, name="mfa_reset_cookie"),
]
