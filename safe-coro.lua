return function(fn)
  coroutine.wrap(function ()
    local success, result = xpcall(fn, debug.traceback)
    if not success then 
      print(err)
    else 
      return result
    end
  end)()
end