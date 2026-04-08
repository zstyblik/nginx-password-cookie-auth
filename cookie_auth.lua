-- nginx-password-cookie-auth - authenticate users with login-password and set a
-- time limited cookie, so they don't have to provide credentials again.
--
-- No warranty. No liability. Use only at your own risk.
--
-- Assembled together by Zdenek Styblik <stybla@turnovfree.net> 2026/Mar/01
local users = {}
users["dog"] = "steak"
users["cat"] = "tuna"

local user = nil
local cookie = ngx.var.cookie_Auth
local cookie_domain = ngx.var.lua_auth_domain
local cookie_secret = ngx.var.lua_auth_secret
local expires_after = tonumber(ngx.var.lua_auth_expires_after)
local hmac = ""
local timestamp = ""

local function table_has_key(table, key)
  return table[key] ~= nil
end

local function set_cookie()
  local expiration = ngx.time() + expires_after
  local token = expiration .. ":" .. ngx.encode_base64(ngx.hmac_sha1(
      ngx.var.lua_auth_secret,
      expiration))
  local cookie = "Auth=" .. token .. "; "
  cookie = cookie .. "Path=/; Domain=" .. cookie_domain .. "; "
  cookie = cookie .. "Expires=" .. ngx.cookie_time(expiration) .. "; "
  cookie = cookie .. "; Max-Age=" .. expires_after .. "; HttpOnly"
  ngx.header['Set-Cookie'] = cookie
end

-- Check that the cookie exists.
if cookie ~= nil and cookie:find(":") ~= nil then
  -- If there's a cookie, split off the HMAC signature
  -- and timestamp.
  local divider = cookie:find(":")
  hmac = ngx.decode_base64(cookie:sub(divider+1))
  timestamp = cookie:sub(0, divider-1)
  -- Verify that the signature is valid.
  if ngx.hmac_sha1(cookie_secret, timestamp) == hmac and tonumber(timestamp) >= ngx.time() then
    ngx.log(ngx.ERR, 'success authenticated by a cookie')
    return
  end
end

if ngx.var.http_authorization then
  local auth = ngx.decode_base64(string.sub(ngx.var.http_authorization, 7))

  local _, _, login, pwd = string.find(auth, "([%w%d]+):([%w%s]+)")
  if (table_has_key(users, login)) and (pwd == users[login]) then
    user = login
    ngx.log(ngx.INFO, 'success loging in')
  end
end

if user then
  ngx.log(ngx.ERR, 'user ' .. user .. ' authenticated')
  set_cookie()
else
  ngx.log(ngx.ERR, 'failure login not authorized')
  ngx.header["WWW-Authenticate"] = 'Basic realm="Restricted"'
  ngx.exit(ngx.HTTP_UNAUTHORIZED)
end
