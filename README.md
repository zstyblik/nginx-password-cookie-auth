# nginx-password-cookie-auth

nginx password cookie auth provides simple way to authenticate users with
login-password credentials and sets a time limitted cookie to reduce the need to
re-authenticate.

You will need nginx with LUA module like eg. Debian's `nginx-extras` or Docker
image [fabiocicerchia/nginx-lua]. Apart from the LUA script itself, nginx config
and docker-compose file are included to give you idea how to use it.

Noteworthy limitations:

* users defined in LUA script itself
* login names must match `a-zA-Z0-9`
* passwords in plaintext
* cookies cannot be revoked once issued which is a common problem
* adjust cookie as needed eg. SameSite, Secure etc.

There might be other limitations. This is a stopgap, not a super-secure solution.

## Settings

* `$lua_auth_domain` - domain to set cookie for.
* `$lua_auth_expires_after` - TTL of cookie.
* `$lua_auth_secret` - HMAC secret.

Unfortunately, usernames and passwords must be defined in LUA script itself.

[fabiocicerchia/nginx-lua]: https://github.com/fabiocicerchia/nginx-lua
