local p = require 'pretty-print-ffi'.prettyPrint
local loop = require 'uv-ffi'

require 'safe-coro'(function ()
  local timer = loop:newTimer()
  p("About to sleep", timer)
  timer:sleep(1000)
  p("Done sleeping!", timer)
  timer:close()    
end)

loop:run('default')