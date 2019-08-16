from django.shortcuts import redirect

from functools import wraps
import time

from .helpers import is_mfa, has_mfa_keys


def multifactor_protected(view_func):
    @wraps(view_func)
    def _wrapped_view_func(request, *args, **kwargs):
        if request.user.is_authenticated:
            if has_mfa_keys(request):
                if not is_mfa(request):
                    request.session['mfa-next'] = request.get_full_path()
                    return redirect('mfa_methods_list')

                next_check = request.session.get('mfa', {}).get('next_check', False)
                if next_check:
                    now = int(time.time())
                    if now >= next_check:
                        request.session['mfa-next'] = request.get_full_path()
                        return redirect(request.session['mfa']['method'].lower() + '_auth')

        return view_func(request, *args, **kwargs)
    return _wrapped_view_func
