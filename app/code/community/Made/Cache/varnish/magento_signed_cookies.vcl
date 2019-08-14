# Implements signed cookie checking with the official Varnish `digest` and `var`
# vmods. The idea is that Magento sends the signed cookie salt and expiry time
# to varnish which are then stored for consecutive requests and cookie
# validation. If the hash check fails or the timestamp has been passed, send
# the client to the backend for revalidation. This timeout can be shorter than
# the PHP session timeout, as we emulate a paywall behaviour.
C{
    #include <sys/types.h>
    #include <time.h>
}C

import digest;
import var;

sub vcl_recv {
    if (var.global_get("cookie_salt") == "") {
        # No cookie signing salt has been set, pass directly to the backend
        return (pass);
    }

    if (digest.hmac_sha1(var.global_get("cookie_salt"), regsub(req.http.Cookie, ".*cookie_expiry=([^;]+).*", "\1")) !=
        regsub(req.http.Cookie, ".*cookie_hash=([^;]+).*", "\1")) {
        # The signed cookie has been tampered with - send to backend
        return (pass);
    }

    # If the signed cookie has expired we send the client to the backend
    var.set_int("current_cookie_expire", std.integer(regsub(req.http.Cookie, ".*cookie_expiry=([^;]+).*", "\1"), 0));
    C{
        time_t current_cookie_expire = (time_t)Vmod_Func_var.get_int(sp, "current_cookie_expire");
        time_t current_time = time(NULL);

        if (current_time > current_cookie_expire) {
            VRT_done(sp, VCL_RET_PASS);
        }
    }C
}

sub vcl_fetch {
    if (beresp.http.X-Cookie-Salt && beresp.http.X-Cookie-Expiry) {
        var.global_set("cookie_salt", beresp.http.X-Cookie-Salt);
        var.global_set("cookie_expiry", beresp.http.X-Cookie-Expiry);

        unset beresp.http.X-Cookie-Salt;
        unset beresp.http.X-Cookie-Expiry;
    }
}
