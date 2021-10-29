local cjson = require('cjson')
local resty_hmac = require('resty.hmac')
local resty_sha256 = require('resty.sha256')
local str = require('resty.string')

local _M = { _VERSION = '0.1.0' }

local function get_credentials ()
  local access_key = os.getenv('GCS_ACCESS_KEY')
  local secret_key = os.getenv('GCS_SECRET_KEY')

  return {
    access_key = access_key,
    secret_key = secret_key
  }
end


local function base64_encoding(data)
    local b='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/' -- from http://lua-users.org/wiki/BaseSixtyFour
    return ((data:gsub('.', function(x)
        local r,b='',x:byte()
        for i=8,1,-1 do r=r..(b%2^i-b%2^(i-1)>0 and '1' or '0') end
        return r;
    end)..'0000'):gsub('%d%d%d?%d?%d?%d?', function(x)
        if (#x < 6) then return '' end
        local c=0
        for i=1,6 do c=c+(x:sub(i,i)=='1' and 2^(6-i) or 0) end
        return b:sub(c+1,c+1)
    end)..({ '', '==', '=' })[#data%3+1])
end


local function get_iso8601_basic(timestamp)
  return os.date('!%Y%m%dT%H%M%SZ', timestamp)
end

local function get_iso8601_basic_short(timestamp)
  return os.date('!%Y%m%d', timestamp)
end

local function get_iso8601_basic_formated(timestamp)
  timestamp = timestamp + 60
  return os.date('!%Y-%m-%dT%H:%M:%SZ', timestamp)
end


local function get_derived_signing_key(keys, timestamp, region, service)
  local h_date = resty_hmac:new('GOOG4' .. keys['secret_key'], resty_hmac.ALGOS.SHA256)
  h_date:update(get_iso8601_basic_short(timestamp))
  local k_date = h_date:final()

  local h_region = resty_hmac:new(k_date, resty_hmac.ALGOS.SHA256)
  h_region:update(region)
  local k_region = h_region:final()

  local h_service = resty_hmac:new(k_region, resty_hmac.ALGOS.SHA256)
  h_service:update(service)
  local k_service = h_service:final()

  local h = resty_hmac:new(k_service, resty_hmac.ALGOS.SHA256)
  h:update('goog4_request')
  return h:final()
end

local function get_cred_scope(timestamp, region, service)
  return get_iso8601_basic_short(timestamp)
    .. '/' .. region
    .. '/' .. service
    .. '/goog4_request'
end

local function get_signed_headers()
  return 'host;x-goog-content-sha256;x-goog-date'
end

local function get_sha256_digest(s)
  local h = resty_sha256:new()
  h:update(s or '')
  return str.to_hex(h:final())
end

local function get_hashed_canonical_request_get(timestamp, host, uri)
  local digest = get_sha256_digest(ngx.var.request_body)
  local canonical_request = ngx.var.request_method .. '\n'
    .. uri .. '\n'
    .. '\n'
    .. 'host:' .. host .. '\n'
    .. 'x-goog-content-sha256:' .. digest .. '\n'
    .. 'x-goog-date:' .. get_iso8601_basic(timestamp) .. '\n'
    .. '\n'
    .. get_signed_headers() .. '\n'
    .. digest
  return get_sha256_digest(canonical_request)
end


local function get_hashed_canonical_request_put(timestamp, host, uri)
  local digest = get_sha256_digest(ngx.var.request.body)
--  local digest = 'UNSIGNED-PAYLOAD'
  local canonical_request = ngx.var.request_method .. '\n'
    .. uri .. '\n'
    .. '\n'
    .. 'host:' .. host .. '\n'
    .. 'x-goog-content-sha256:' .. digest .. '\n'
    .. 'x-goog-date:' .. get_iso8601_basic(timestamp) .. '\n'
    .. '\n'
    .. get_signed_headers() .. '\n'
    .. digest
  return get_sha256_digest(canonical_request)
end


local function get_string_to_sign(timestamp, region, service, host, uri, keys)
  if ngx.var.request_method == "GET" then
     return 'GOOG4-HMAC-SHA256\n'
        .. get_iso8601_basic(timestamp) .. '\n'
        .. get_cred_scope(timestamp, region, service) .. '\n'
        .. get_hashed_canonical_request_get(timestamp, host, uri)
  else
     local cred =  keys['access_key'] .. '/' .. get_cred_scope(timestamp, region, service)

     local x_algo = '{"x-goog-algorithm": "GOOG4-HMAC-SHA256"},'
     local x_cred = '{"x-goog-credential": ' .. '"' .. cred .. '"},'
     local x_date = '{"x-goog-date": ' .. '"' ..get_iso8601_basic(timestamp) .. '"}'

     local post_policy = '{ "expiration": ' .. '"' .. get_iso8601_basic_formated(timestamp) .. '",'
                        .. '   "conditions": ' .. '[ {"bucket": "ccmn4-bucket-test-v4" }, {"acl": "private"},'
                        .. x_cred
                        .. x_algo
                        .. x_date
                        .. ']}'
     print (cjson.encode(post_policy))
     local json_post_policy = cjson.encode(post_policy)
     local b64_post_policy = base64_encoding(json_post_policy)
     print (b64_post_policy)
     return b64_post_policy
  end
end


local function get_signature(derived_signing_key, string_to_sign)
  local h = resty_hmac:new(derived_signing_key, resty_hmac.ALGOS.SHA256)
  h:update(string_to_sign)
  return h:final(nil, true)
end

local function get_authorization(keys, timestamp, region, service, host, uri)
  local derived_signing_key = get_derived_signing_key(keys, timestamp, region, service)
  local string_to_sign = get_string_to_sign(timestamp, region, service, host, uri, keys)
  local auth = 'GOOG4-HMAC-SHA256 '
       .. 'Credential=' .. keys['access_key'] .. '/' .. get_cred_scope(timestamp, region, service)
       .. ', SignedHeaders=' .. get_signed_headers()
       .. ', Signature=' .. get_signature(derived_signing_key, string_to_sign)
  return auth
end

function _M.goog_set_headers(host, uri)
  local creds = get_credentials()
  local timestamp = tonumber(ngx.time())
  local service = 'storage'
  local region = 'auto'
  local auth = get_authorization(creds, timestamp, region, service, host, uri)

  ngx.req.set_header('Authorization', auth)
  ngx.req.set_header('Host', host)
  ngx.req.set_header('x-goog-date', get_iso8601_basic(timestamp))

  if ngx.var.request_method == "POST" then
     ngx.req.set_header('Content-Type', 'application/json')
  end
  
end

function _M.gcs_set_headers(host, uri)
  _M.goog_set_headers(host, uri)
  ngx.req.set_header('x-goog-content-sha256', get_sha256_digest(ngx.var.request_body))
end

return _M
