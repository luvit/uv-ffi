local loop = require 'uv-ffi'

local function normalize(options)
  local t = type(options)
  if t == 'string' then
    options = {path = options}
  elseif t == 'number' then
    options = {port = options}
  elseif t ~= 'table' then
    assert('Net options must be table, string, or number')
  end
  if options.port or options.host then
    options.isTcp = true
    options.host = options.host or '127.0.0.1'
    assert(options.port, 'options.port is required for tcp connections')
  elseif options.path then
    options.isTcp = false
  else
    error('Must set either options.path or options.port')
  end
  return options
end

return function(options)
  local socket
  options = normalize(options)
  if options.isTcp then
    local res =
      assert(
      loop:getaddrinfo(
        options.host,
        options.port,
        {
          socktype = options.socktype,
          family = options.family
        }
      )[1]
    )
    socket = loop:newTcp()
    socket:connect(res.addr, res.port)
  else
    socket = loop:newPipe(false)
    socket:connect(options.path)
  end
  return socket
end
