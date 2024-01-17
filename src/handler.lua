-- This file has been modified by "ilovetypescript" from the original provided by Optum.
local basic_serializer = require "kong.plugins.kong-splunk-log-customized.basic"
local Queue = require "kong.tools.queue"
local luajwt = require "kong.plugins.kong-splunk-log-customized.luajwt"

local cjson = require "cjson"
local url = require "socket.url"
local http = require "resty.http"
local cjson_encode = cjson.encode
local table_concat = table.concat
local tostring = tostring
local tonumber = tonumber
local fmt = string.format
local pairs = pairs
local max = math.max

local KongSplunkLog = {}

KongSplunkLog.PRIORITY = 14
KongSplunkLog.VERSION = "3.9.1"

-- Create a function that concatenates multiple JSON objects into a JSON array.
-- This saves us from rendering all entries into one large JSON string.
-- Each invocation of the function returns the next bit of JSON, i.e. the opening
-- bracket, the entries, delimiting commas and the closing bracket.
-- UPDATE: Edited to not have leading/trailing []'s and no commas between entries for splunk format logging.
local function make_splunk_json_array_payload_function(conf, entries)
  if conf.queue.max_batch_size == 1 then
    return #entries[1], entries[1]
  end

  local nentries = #entries

  local content_length = 1
  for i = 1, nentries do
    content_length = content_length + #entries[i] + 1
  end

  local i = 0
  local last = max(2, nentries * 2 + 1)
  return content_length, function()
    i = i + 1

    if i == 1 then
      return ''

    elseif i < last then
      return i % 2 == 0 and entries[i / 2] or '\n\n'

    elseif i == last then
      return ''
    end
  end
end


local parsed_urls_cache = {}


local function t2s(o)
  if type(o) == 'table' then
    local s = '{ '
    for k, v in pairs(o) do
      if type(k) ~= 'number' then k = '"' .. k .. '"' end
      s = s .. '[' .. k .. '] = ' .. t2s(v) .. ','
    end

    return s .. '} '
  else
    return tostring(o)
  end
end

-- Parse host url.
-- @param `url` host url
-- @return `parsed_url` a table with host details:
-- scheme, host, port, path, query, userinfo
local function parse_url(host_url)
  local parsed_url = parsed_urls_cache[host_url]

  if parsed_url then
    return parsed_url
  end

  parsed_url = url.parse(host_url)
  if not parsed_url.port then
    if parsed_url.scheme == "http" then
      parsed_url.port = 80

    elseif parsed_url.scheme == "https" then
      parsed_url.port = 443
    end
  end
  if not parsed_url.path then
    parsed_url.path = "/"
  end

  parsed_urls_cache[host_url] = parsed_url

  return parsed_url
end

-- Sends the provided payload (a string) to the configured plugin host
-- @return true if everything was sent correctly, falsy if error
-- @return error message if there was an error
local function send_payload(conf, entries)
  local method = conf.method
  local timeout = conf.timeout
  local keepalive = conf.keepalive
  local content_type = conf.content_type
  local http_endpoint = conf.splunk_endpoint
  local splunk_token = conf.splunk_access_token

  local ok, err
  local parsed_url = parse_url(http_endpoint)
  local host = parsed_url.host
  local port = tonumber(parsed_url.port)

  local httpc = http.new()
  httpc:set_timeout(timeout)
  ok, err = httpc:connect(host, port)
  if not ok then
    return nil, "failed to connect to " .. host .. ":" .. tostring(port) .. ": " .. err
  end

  if parsed_url.scheme == "https" then
    local _, err = httpc:ssl_handshake(true, host, false)
    if err then
      return nil, "failed to do SSL handshake with " ..
          host .. ":" .. tostring(port) .. ": " .. err
    end
  end
  
  local content_length, payload = make_splunk_json_array_payload_function(conf, entries)
  
  local res, err = httpc:request({
    method = method,
    path = parsed_url.path,
    query = parsed_url.query,
    headers = {
      ["Host"] = parsed_url.host,
      ["Content-Type"] = content_type,
      ["Content-Length"] = content_length,
      ["Authorization"] = "Splunk " .. splunk_token,
    },
    body = payload,
  })
  if not res then
    return nil, "failed request to " .. host .. ":" .. tostring(port) .. ": " .. err
  end

  -- always read response body, even if we discard it without using it on success
  local response_body = res:read_body()
  local success = res.status < 400
  local err_msg

  if not success then
    err_msg = "request to " .. host .. ":" .. tostring(port) ..
        " returned status code " .. tostring(res.status) .. " and body " ..
        response_body
  end

  ok, err = httpc:set_keepalive(keepalive)
  if not ok then
    -- the batch might already be processed at this point, so not being able to set the keepalive
    -- will not return false (the batch might not need to be reprocessed)
    kong.log.err("failed keepalive for ", host, ":", tostring(port), ": ", err)
  end

  return success, err_msg
end

local function json_array_concat(entries)
  --return "[" .. table_concat(entries, ",") .. "]" If splunk followed true json format we would use this
  return "" .. table_concat(entries, "\n\n") .. "" -- Break events up by newlining them
end
-- Create a queue name from the same legacy parameters that were used in the
-- previous queue implementation.  This ensures that http-log instances that
-- have the same log server parameters are sharing a queue.  It deliberately
-- uses the legacy parameters to determine the queue name, even though they may
-- be nil in newer configurations.  Note that the modernized queue related
-- parameters are not included in the queue name determination.
local function make_queue_name(conf)
  return fmt("%s:%s:%s:%s:%s:%s:%s:%s:%s:%s:%s:%s:%s:%s:%s:%s",
          conf.splunk_endpoint,
          conf.method,
          conf.content_type,
          conf.timeout,
          conf.keepalive,
          conf.retry_count,
          conf.queue_size,
          conf.flush_timeout,
          conf.splunk_index,
          conf.splunk_sourcetype,
          conf.includebody,
          conf.includeresponse,
          conf.includejwt,
          conf.includeheaders,
          conf.includeBearerTokenHeader,
          conf.includejwtdecoded)
end

function KongSplunkLog:access(conf)
  local body
  local jwt
  local decodedJwt
  local err
  local headers
  if conf.includebody == 1 then
    body, error = kong.request.get_raw_body()
    if not body then
      body = error
    else
      body = string.sub(body, 1, 2048)
    end
  else
    body = "Set includebody = 1"
  end
  kong.ctx.plugin.request_body = body

  if conf.includejwt == 1 or conf.includeBearerTokenHeader == 1 then
    jwt = kong.request.get_header("Authorization")
    -- Check if the token is in the header otherwise check access_token querystring param
    if not (jwt == nil) then
      if not string.match(string.lower(jwt), "bearer") then
        jwt = kong.request.get_query_arg("access_token")
      end
    end

    if not jwt then
      jwt = "No access token in Authorization Bearer header or in access_token querystring parameter"
    else
      if not (jwt == nil) then
        jwt = string.gsub(jwt, "Bearer ", "")
        if conf.includejwt == 1 then
          decodedJwt, err = luajwt.decode(jwt, "", false)
          if not err then
            kong.ctx.plugin.jwt_aud = decodedJwt.aud -- Intended audience for the token (clientId for the API)
            kong.ctx.plugin.jwt_azp = decodedJwt.azp -- applicationId for the client in Azure AD
            kong.ctx.plugin.jwt_oid = decodedJwt.oid -- Id of the requestor in Azure AD
            if conf.includejwtdecoded == 1 then
              kong.ctx.plugin.jwt_decoded = t2s(decodedJwt)
            end
          else
            kong.ctx.plugin.jwt_aud = err -- Intended audience for the token (clientId for the API)
            kong.ctx.plugin.jwt_azp = err -- applicationId for the client in Azure AD
            kong.ctx.plugin.jwt_oid = err -- Id of the requestor in Azure AD
          end
        end
        if conf.includeBearerTokenHeader ~= 1 then
          jwt = "Set includeBearerTokenHeader = 1"
        end
      end
    end
  else
    jwt = "Not captured"
  end
  kong.ctx.plugin.request_jwt = jwt

  if conf.includeheaders == 1 then
    headers = kong.request.get_headers()
    if not headers then
      kong.ctx.plugin.request_headers = ""
    else
      kong.ctx.plugin.request_headers = t2s(headers)
    end
  else
    kong.ctx.plugin.request_headers = "Set includeheaders = 1"
  end
end

function KongSplunkLog:body_filter(conf)
  local body
  if conf.includeresponse == 1 then
    body, error = kong.response.get_raw_body()
    if not body then
      body = error
    else
      body = string.sub(body, 1, 2048)
    end
  else
    body = "Set includeresponse = 1"
  end
  kong.ctx.plugin.response_body = body
end

function KongSplunkLog:log(conf)

  local queue_conf = Queue.get_plugin_params("kong-splunk-log-customized", conf, make_queue_name(conf))
  kong.log.debug("Queue name automatically configured based on configuration parameters to: ", queue_conf.name)

  local ok, err = Queue.enqueue(
    queue_conf,
    send_payload,
    conf,
    cjson_encode(basic_serializer.serialize(ngx))
  )
  if not ok then
    kong.log.err("Failed to enqueue log entry to log server: ", err)
  end
end

return KongSplunkLog
