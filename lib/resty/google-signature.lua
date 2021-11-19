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

local function get_hashed_canonical_request(timestamp, host, uri)
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


local function get_string_to_sign(timestamp, region, service, host, uri, keys)
   return 'GOOG4-HMAC-SHA256\n'
        .. get_iso8601_basic(timestamp) .. '\n'
        .. get_cred_scope(timestamp, region, service) .. '\n'
        .. get_hashed_canonical_request(timestamp, host, uri)
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
end

function _M.gcs_set_headers(host, uri)
   if ngx.var.request_method == "POST" then
      ngx.print("Invalid Method: ", ngx.var.request_method)
      return _M
   else
      _M.goog_set_headers(host, uri)
      ngx.req.set_header('x-goog-content-sha256', get_sha256_digest(ngx.var.request_body))
  end
end


return _M
