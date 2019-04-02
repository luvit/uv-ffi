local Connection = require 'connection'

-- This is a simple wrapper around raw libuv streams that lets
-- us have pull-style streams with a nice coroutine based interface.
-- Read calls will block till there is data.
-- Write calls will block will the buffer is no longer full (applying backpressure).
-- The read calls will automatically pause and resume the read stream to apply
-- backpressure to the remote writer as well.
return function(socket, onError)
  local paused = true
  local stream = Connection.newPush()
  local cb

  local function onRead(error, value)
    -- p('in', value)
    if error and onError then
      onError(error)
    end
    return stream.onChunk(value)
  end

  function stream.onStart()
    if not paused then
      return
    end
    paused = false
    cb = socket:readStart(cb or onRead)
  end

  function stream.onStop()
    if paused then
      return
    end
    paused = true
    socket:readStop()
  end

  function stream.writeChunk(value)
    -- p('out', value)
    if value then
      socket:write(value)
    else
      socket:shutdown()
    end
  end

  stream.socket = socket
  return stream
end
