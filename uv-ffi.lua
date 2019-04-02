local ffi = require 'ffi'
local cast = ffi.cast
local C = ffi.C
local UV = ffi.load('uv')

if ffi.os == 'Windows' then
  ffi.cdef [[
    typedef struct uv_buf_t {
      ULONG len;
      char* base;
    } uv_buf_t;
  ]]
else
  ffi.cdef [[
    typedef struct uv_buf_t {
      char* base;
      size_t len;
    } uv_buf_t;
  ]]
end

ffi.cdef [[
  uv_buf_t uv_buf_init(char* base, unsigned int len);

  typedef enum {
    UV_EOF = -4095
  } uv_errno_t;

  typedef enum {
    UV_UNKNOWN_HANDLE = 0,
    UV_ASYNC,
    UV_CHECK,
    UV_FS_EVENT,
    UV_FS_POLL,
    UV_HANDLE,
    UV_IDLE,
    UV_NAMED_PIPE,
    UV_POLL,
    UV_PREPARE,
    UV_PROCESS,
    UV_STREAM,
    UV_TCP,
    UV_TIMER,
    UV_TTY,
    UV_UDP,
    UV_SIGNAL,
    UV_FILE,
    UV_HANDLE_TYPE_MAX
  } uv_handle_type;

  typedef enum {
    UV_UNKNOWN_REQ = 0,
    UV_REQ,
    UV_CONNECT,
    UV_WRITE,
    UV_SHUTDOWN,
    UV_UDP_SEND,
    UV_FS,
    UV_WORK,
    UV_GETADDRINFO,
    UV_GETNAMEINFO,
    UV_REQ_TYPE_MAX,
  } uv_req_type;

  size_t uv_loop_size(void);
  size_t uv_req_size(uv_req_type type);
  size_t uv_handle_size(uv_handle_type type);
]]

ffi.cdef(
  string.format(
    [[
    struct uv_loop_s {uint8_t _[%d];};
    struct uv_connect_s {uint8_t _[%d];};
    struct uv_write_s {uint8_t _[%d];};
    struct uv_shutdown_s {uint8_t _[%d];};
    struct uv_getaddrinfo_s {uint8_t _[%d];};
    struct uv_tcp_s {uint8_t _[%d];};
    struct uv_tty_s {uint8_t _[%d];};
    struct uv_pipe_s {uint8_t _[%d];};
    struct uv_timer_s {uint8_t _[%d];};
  ]],
    tonumber(UV.uv_loop_size()),
    tonumber(UV.uv_req_size(UV.UV_CONNECT)),
    tonumber(UV.uv_req_size(UV.UV_WRITE)),
    tonumber(UV.uv_req_size(UV.UV_SHUTDOWN)),
    tonumber(UV.uv_req_size(UV.UV_GETADDRINFO)),
    tonumber(UV.uv_handle_size(UV.UV_TCP)),
    tonumber(UV.uv_handle_size(UV.UV_TTY)),
    tonumber(UV.uv_handle_size(UV.UV_NAMED_PIPE)),
    tonumber(UV.uv_handle_size(UV.UV_TIMER))
  )
)

ffi.cdef [[
  typedef struct uv_loop_s uv_loop_t;
  typedef struct uv_req_s uv_req_t;
  typedef struct uv_write_s uv_write_t;
  typedef struct uv_connect_s uv_connect_t;
  typedef struct uv_shutdown_s uv_shutdown_t;
  typedef struct uv_getaddrinfo_s uv_getaddrinfo_t;
  typedef struct uv_handle_s uv_handle_t;
  typedef struct uv_stream_s uv_stream_t;
  typedef struct uv_tcp_s uv_tcp_t;
  typedef struct uv_tty_s uv_tty_t;
  typedef struct uv_pipe_s uv_pipe_t;
  typedef struct uv_timer_s uv_timer_t;

  typedef enum uv_run_mode_e {
    UV_RUN_DEFAULT = 0,
    UV_RUN_ONCE,
    UV_RUN_NOWAIT
  } uv_run_mode;

  int uv_ip4_addr(const char* ip, int port, struct sockaddr_in* addr);
  int uv_ip6_addr(const char* ip, int port, struct sockaddr_in6* addr);
  int uv_ip4_name(const struct sockaddr_in* src, char* dst, size_t size);
  int uv_ip6_name(const struct sockaddr_in6* src, char* dst, size_t size);
  int uv_inet_ntop(int af, const void* src, char* dst, size_t size);
  int uv_inet_pton(int af, const char* src, void* dst);

  const char* uv_err_name(int err);
  const char* uv_strerror(int err);
]]

local function makeCallback(type)
  local thread, isMain = coroutine.running()
  if not thread or isMain then return end
  local cb
  cb =
    cast(
    type,
    function(...)
      -- print('oncall', ...)
      cb:free()
      assert(coroutine.resume(thread, ...))
    end
  )
  return cb
end

local function uvGetError(status)
  return ffi.string(UV.uv_err_name(status)) .. ': ' .. ffi.string(UV.uv_strerror(status))
end

local function uvCheck(status)
  if status < 0 then
    error(uvGetError(status))
  else
    return status
  end
end

local Loop = {}

-------------------------------------------------------------------------------
-- Req
-------------------------------------------------------------------------------

ffi.cdef [[
  int uv_cancel(uv_req_t* req);
  uv_req_type uv_req_get_type(const uv_req_t* req);
  const char* uv_req_type_name(uv_req_type type);
]]

local Req = {}

function Req:cancel()
  return uvCheck(UV.uv_cancel(cast('uv_req_t*', self)))
end

function Req:getType()
  local id = UV.uv_req_get_type(cast('uv_req_t*', self))
  return ffi.string(UV.uv_req_type_name(id))
end

-------------------------------------------------------------------------------
-- Connect
-------------------------------------------------------------------------------

local Connect = setmetatable({}, {__index = Req})
Connect.type = ffi.typeof 'uv_connect_t'
ffi.metatype(Connect.type, {__index = Connect})
function Connect.new()
  return Connect.type()
end

-------------------------------------------------------------------------------
-- Write
-------------------------------------------------------------------------------

local Write = setmetatable({}, {__index = Req})
Write.type = ffi.typeof 'uv_write_t'
ffi.metatype(Write.type, {__index = Write})
function Write.new()
  return Write.type()
end

-------------------------------------------------------------------------------
-- Shutdown
-------------------------------------------------------------------------------

local Shutdown = setmetatable({}, {__index = Req})
Shutdown.type = ffi.typeof 'uv_shutdown_t'
ffi.metatype(Shutdown.type, {__index = Shutdown})
function Shutdown.new()
  return Shutdown.type()
end

-------------------------------------------------------------------------------
-- Getaddrinfo
-------------------------------------------------------------------------------

ffi.cdef [[
  enum {
    AF_UNSPEC = 0,
    AF_INET = 2,
    AF_INET6 = 10
  };
  enum {
    SOCK_STREAM = 1,
    SOCK_DGRAM = 2
  };

  typedef int32_t socklen_t;

  struct addrinfo {
    int              ai_flags;
    int              ai_family;
    int              ai_socktype;
    int              ai_protocol;
    socklen_t        ai_addrlen;
    struct sockaddr *ai_addr;
    char            *ai_canonname;
    struct addrinfo *ai_next;
  };

  typedef void (*uv_getaddrinfo_cb)(uv_getaddrinfo_t* req, int status, struct addrinfo* res);

  int uv_getaddrinfo(
    uv_loop_t* loop, uv_getaddrinfo_t* req, uv_getaddrinfo_cb getaddrinfo_cb,
    const char* node, const char* service, const struct addrinfo* hints
  );
  void uv_freeaddrinfo(struct addrinfo* ai);
]]

local Getaddrinfo = setmetatable({}, {__index = Req})
Getaddrinfo.type = ffi.typeof 'uv_getaddrinfo_t'
ffi.metatype(Getaddrinfo.type, {__index = Getaddrinfo})
function Getaddrinfo.new()
  return Getaddrinfo.type()
end

local families = {
  inet = UV.AF_INET,
  inet6 = UV.AF_INET6,
  [UV.AF_INET] = 'inet',
  [UV.AF_INET6] = 'inet6'
}

local socktypes = {
  stream = UV.SOCK_STREAM,
  dgram = UV.SOCK_DGRAM,
  [UV.SOCK_STREAM] = 'stream',
  [UV.SOCK_DGRAM] = 'dgram'
}

function Loop:getaddrinfo(node, service, hints)
  local req = Getaddrinfo.new()
  p(req)
  local opts = ffi.new('struct addrinfo')
  if type(service) == 'number' then
    service = tostring(service)
  end
  if hints then
    if hints.family then
      opts.ai_family = assert(families[hints.family], 'Unknown family name')
    end
    if hints.socktype then
      opts.ai_socktype = assert(socktypes[hints.socktype], 'Unknown socktype name')
    end
  end
  p(node, service, hints)
  uvCheck(UV.uv_getaddrinfo(self, req, makeCallback 'uv_getaddrinfo_cb', node, service, opts))
  local _, status, res = coroutine.yield()
  uvCheck(status)
  local results = {}
  local i = 1
  while res ~= nil do
    local family = families[res.ai_family]
    local socktype = socktypes[res.ai_socktype]
    local entry = {
      family = family,
      socktype = socktype
    }
    results[i] = entry
    i = i + 1
    if family == 'inet' then
      local buf = ffi.new 'char[16]'
      local addr = cast('const struct sockaddr_in*', res.ai_addr)
      uvCheck(UV.uv_ip4_name(addr, buf, 16))
      entry.addr = ffi.string(buf)
      entry.port = C.ntohs(addr.sin_port)
    elseif family == 'inet6' then
      local buf = ffi.new 'char[46]'
      local addr = cast('const struct sockaddr_in6*', res.ai_addr)
      uvCheck(UV.uv_ip6_name(addr, buf, 46))
      entry.addr = ffi.string(buf)
      entry.port = C.ntohs(addr.sin6_port)
    end
    res = res.ai_next
  end
  return results
end

-------------------------------------------------------------------------------
-- Handle
-------------------------------------------------------------------------------

ffi.cdef [[
  typedef void (*uv_walk_cb)(uv_handle_t* handle, void* arg);
  typedef void (*uv_close_cb)(uv_handle_t* handle);
  typedef void (*uv_alloc_cb)(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf);

  struct sockaddr {
    unsigned short    sa_family;
    char              sa_data[14];
  };

  struct in_addr {
    unsigned long s_addr;
  };

  struct sockaddr_in {
    short            sin_family;
    unsigned short   sin_port;
    struct in_addr   sin_addr;
    char             sin_zero[8];
  };

  struct in6_addr {
    unsigned char   s6_addr[16];
  };

  struct sockaddr_in6 {
    uint16_t        sin6_family;
    uint16_t        sin6_port;
    uint32_t        sin6_flowinfo;
    struct in6_addr sin6_addr;
    uint32_t        sin6_scope_id;
  };

  typedef uint16_t sa_family_t;

  struct sockaddr_storage {
    sa_family_t  ss_family;
    char      __ss_pad1[6];
    int64_t   __ss_align;
    char      __ss_pad2[112];
  };

  uint32_t htonl(uint32_t hostlong);
  uint16_t htons(uint16_t hostshort);
  uint32_t ntohl(uint32_t netlong);
  uint16_t ntohs(uint16_t netshort);

  void *malloc(size_t size);
  void free(void *ptr);

  typedef int uv_file;

  uv_handle_type uv_guess_handle(uv_file file);

  int uv_is_active(const uv_handle_t* handle);
  int uv_is_closing(const uv_handle_t* handle);
  void uv_close(uv_handle_t* handle, uv_close_cb close_cb);
  void uv_ref(uv_handle_t* handle);
  void uv_unref(uv_handle_t* handle);
  int uv_has_ref(const uv_handle_t* handle);
  int uv_send_buffer_size(uv_handle_t* handle, int* value);
  int uv_recv_buffer_size(uv_handle_t* handle, int* value);
  uv_loop_t* uv_handle_get_loop(const uv_handle_t* handle);
  void* uv_handle_get_data(const uv_handle_t* handle);
  void* uv_handle_set_data(uv_handle_t* handle, void* data);
  uv_handle_type uv_handle_get_type(const uv_handle_t* handle);
  const char* uv_handle_type_name(uv_handle_type type);
]]

local function onAlloc(handle, suggestedSize, buf)
  local cached = cast('uv_buf_t*', UV.uv_handle_get_data(handle))
  if cached ~= nil then
    buf.base = cached.base
    buf.len = cached.len
  else
    local base = C.malloc(suggestedSize)
    buf.base = base
    buf.len = suggestedSize
    -- Store the data in handle->data as a uv_buf_t*
    local data = cast('uv_buf_t*', C.malloc(ffi.sizeof 'uv_buf_t'))
    data.base = base
    data.len = suggestedSize
    UV.uv_handle_set_data(handle, data)
  end
end

local allocCb = cast('uv_alloc_cb', onAlloc)

function Loop.guessHandle(fd)
  return ffi.string(UV.uv_handle_type_name(UV.uv_guess_handle(fd)))
end

local Handle = {}

function Handle:isActive()
  return UV.uv_is_active(cast('uv_handle_t*', self)) ~= 0
end

function Handle:isClosing()
  return UV.uv_is_closing(cast('uv_handle_t*', self)) ~= 0
end

function Handle:close()
  local handle = cast('uv_handle_t*', self)
  local _, main = coroutine.running()
  if main then
    UV.uv_close(handle, nil)
  else
    UV.uv_close(handle, makeCallback 'uv_close_cb')
    coroutine.yield()
  end
  local cached = cast('uv_buf_t*', UV.uv_handle_get_data(handle))
  if cached ~= nil then
    C.free(cached.base)
    C.free(cached)
  end
end

function Handle:ref()
  return UV.uv_ref(cast('uv_handle_t*', self))
end

function Handle:unref()
  return UV.uv_unref(cast('uv_handle_t*', self))
end

function Handle:hasRef()
  return UV.uv_has_ref(cast('uv_handle_t*', self)) ~= 0
end

function Handle:setSendBufferSize(value)
  uvCheck(UV.uv_send_buffer_size(cast('uv_handle_t*', self), value))
end

function Handle:getSendBufferSize()
  local out = ffi.new('int[1]')
  uvCheck(UV.uv_send_buffer_size(cast('uv_handle_t*', self), out))
  return out[0]
end

function Handle:setRecvBufferSize(value)
  uvCheck(UV.uv_recv_buffer_size(cast('uv_handle_t*', self), value))
end

function Handle:getRecvBufferSize()
  local out = ffi.new('int[1]')
  uvCheck(UV.uv_recv_buffer_size(cast('uv_handle_t*', self), out))
  return out[0]
end

function Handle:getLoop()
  return UV.uv_handle_get_loop(cast('uv_handle_t*', self))
end

function Handle:getType()
  local id = UV.uv_handle_get_type(cast('uv_handle_t*', self))
  return ffi.string(UV.uv_handle_type_name(id))
end

-------------------------------------------------------------------------------
-- Stream
-------------------------------------------------------------------------------

ffi.cdef [[
  typedef void (*uv_read_cb)(uv_stream_t* stream, int64_t nread, const uv_buf_t* buf);
  typedef void (*uv_write_cb)(uv_write_t* req, int status);
  typedef void (*uv_connect_cb)(uv_connect_t* req, int status);
  typedef void (*uv_shutdown_cb)(uv_shutdown_t* req, int status);
  typedef void (*uv_connection_cb)(uv_stream_t* server, int status);

  int uv_shutdown(uv_shutdown_t* req, uv_stream_t* handle, uv_shutdown_cb cb);
  int uv_listen(uv_stream_t* stream, int backlog, uv_connection_cb cb);
  int uv_accept(uv_stream_t* server, uv_stream_t* client);
  int uv_read_start(uv_stream_t* stream, uv_alloc_cb alloc_cb, uv_read_cb read_cb);
  int uv_read_stop(uv_stream_t*);
  int uv_write(uv_write_t* req, uv_stream_t* handle, const uv_buf_t bufs[], unsigned int nbufs, uv_write_cb cb);
  int uv_write2(uv_write_t* req, uv_stream_t* handle, const uv_buf_t bufs[], unsigned int nbufs, 
                uv_stream_t* send_handle, uv_write_cb cb);
  int uv_try_write(uv_stream_t* handle, const uv_buf_t bufs[], unsigned int nbufs);
  int uv_is_readable(const uv_stream_t* handle);
  int uv_is_writable(const uv_stream_t* handle);
  int uv_stream_set_blocking(uv_stream_t* handle, int blocking);
  size_t uv_stream_get_write_queue_size(const uv_stream_t* stream);
]]

local Stream = setmetatable({}, {__index = Handle})

function Stream:shutdown()
  local req = Shutdown.new()
  uvCheck(UV.uv_shutdown(req, cast('uv_stream_t*', self), makeCallback 'uv_shutdown_cb'))
  local _, status = coroutine.yield()
  uvCheck(status)
end

function Stream:listen(backlog, onConnection)
  local cb = cast('uv_connection_cb', onConnection)
  uvCheck(UV.uv_listen(cast('uv_stream_t*', self), backlog, cb))
  return cb
end

function Stream:accept(client)
  uvCheck(UV.uv_accept(cast('uv_stream_t*', self), cast('uv_stream_t*', client)))
end

function Stream:readStart(onRead)
  local function onEvent(_, status, buf)
    print('onRead', _, status, buf)
    if status == 0 then
      return
    end
    if status == UV.UV_EOF then
      onRead(nil)
    elseif status < 0 then
      return onRead(uvGetError(status))
    else
      onRead(nil, ffi.string(buf.base, status))
    end
  end
  local cb = cast('uv_read_cb', onEvent)
  uvCheck(UV.uv_read_start(cast('uv_stream_t*', self), allocCb, cb))
end

function Stream:readStop()
  uvCheck(UV.uv_read_stop(cast('uv_stream_t*', self)))
end

function Stream:write(data)
  local req = Write.new()
  local bufs = ffi.new('uv_buf_t[1]')
  bufs[0].base = cast('char*', data)
  bufs[0].len = #data
  local cb = makeCallback 'uv_write_cb'
  uvCheck(UV.uv_write(req, cast('uv_stream_t*', self), bufs, 1, cb))
  if cb then
    local _, status = coroutine.yield()
    uvCheck(status)
  end
end

function Stream:write2(handle)
  local req = Write.new()
  local cb = makeCallback 'uv_write_cb'
  uvCheck(UV.uv_write(req, cast('uv_stream_t*', self), nil, 0, cast('uv_stream_t*', handle), cb))
  local _, status = coroutine.yield()
  uvCheck(status)
end

function Stream:tryWrite(data)
  local bufs = ffi.new('uv_buf_t[1]')
  bufs[0].base = cast('char*', data)
  bufs[0].len = #data
  return uvCheck(UV.uv_try_write(cast('uv_stream_t*', self), bufs, 1))
end

function Stream:isReadable()
  return UV.uv_is_readable(cast('uv_stream_t*', self)) ~= 0
end

function Stream:isWritable()
  return UV.uv_is_writable(cast('uv_stream_t*', self)) ~= 0
end

function Stream:setBlocking(blocking)
  uvCheck(UV.uv_set_blocking(cast('uv_stream_t*', self), blocking))
end

function Stream:getWriteQueueSize()
  return tonumber(UV.uv_stream_get_write_queue_size(cast('uv_stream_t*', self)))
end

-------------------------------------------------------------------------------
-- Tcp
-------------------------------------------------------------------------------

ffi.cdef [[
  int uv_tcp_init(uv_loop_t* loop, uv_tcp_t* handle);
  int uv_tcp_bind(uv_tcp_t* handle, const struct sockaddr* addr, unsigned int flags);
  int uv_tcp_connect(uv_connect_t* req, uv_tcp_t* handle, const struct sockaddr_in* addr, uv_connect_cb cb);
]]

local Tcp = setmetatable({}, {__index = Stream})
Tcp.type = ffi.typeof 'uv_tcp_t'

function Loop:newTcp()
  local tcp = Tcp.type()
  uvCheck(UV.uv_tcp_init(self, tcp))
  return tcp
end

function Tcp:getsockname()
  -- TODO: Improve output
  return UV.uv_tcp_getsockname(self)
end

function Tcp:getpeername()
  -- TODO: Improve output
  return UV.uv_tcp_getpeername(self)
end

function Tcp:connect(host, port)
  local req = Connect.new()
  local addr = ffi.new 'struct sockaddr_in'
  UV.uv_ip4_addr(host, port, addr)
  uvCheck(UV.uv_tcp_connect(req, self, addr, makeCallback 'uv_connect_cb'))
  local _, status = coroutine.yield()
  uvCheck(status)
end

ffi.metatype(Tcp.type, {__index = Tcp})

-------------------------------------------------------------------------------
-- Tty
-------------------------------------------------------------------------------

ffi.cdef [[
  typedef enum {
    /* Initial/normal terminal mode */
    UV_TTY_MODE_NORMAL,
    /* Raw input mode (On Windows, ENABLE_WINDOW_INPUT is also enabled) */
    UV_TTY_MODE_RAW,
    /* Binary-safe I/O mode for IPC (Unix-only) */
    UV_TTY_MODE_IO
  } uv_tty_mode_t;

  int uv_tty_init(uv_loop_t* loop, uv_tty_t* handle, uv_file fd, int unused);
  int uv_tty_set_mode(uv_tty_t* handle, uv_tty_mode_t mode);
  int uv_tty_reset_mode(void);
  int uv_tty_get_winsize(uv_tty_t* handle, int* width, int* height);
]]

local Tty = setmetatable({}, {__index = Stream})
Tty.type = ffi.typeof 'uv_tty_t'

function Loop:newTty(fd)
  local tty = Tty.type()
  uvCheck(UV.uv_tty_init(self, tty, fd, 0))
  return tty
end

function Tty:setMode(mode)
  uvCheck(
    UV.uv_tty_set_mode(self, assert(UV['UV_TTY_MODE_' .. string.upper(mode)], 'Unknown tty mode'))
  )
end

function Tty:resetMode()
  uvCheck(UV.uv_tty_reset_mode())
end

function Tty:getWinsize()
  local width = ffi.new('int[1]')
  local height = ffi.new('int[1]')
  uvCheck(UV.uv_tty_get_winsize(self, width, height))
  return tonumber(width[0]), tonumber(height[0])
end

ffi.metatype(Tty.type, {__index = Tty})

-------------------------------------------------------------------------------
-- Pipe
-------------------------------------------------------------------------------

ffi.cdef [[
  int uv_pipe_init(uv_loop_t* loop, uv_pipe_t* handle, int ipc);
  int uv_pipe_open(uv_pipe_t* handle, uv_file file);
  int uv_pipe_bind(uv_pipe_t* handle, const char* name);
  void uv_pipe_connect(uv_connect_t* req, uv_pipe_t* handle, const char* name, uv_connect_cb cb);
  int uv_pipe_getsockname(const uv_pipe_t* handle, char* buffer, size_t* size);
  int uv_pipe_getpeername(const uv_pipe_t* handle, char* buffer, size_t* size);
  void uv_pipe_pending_instances(uv_pipe_t* handle, int count);
  int uv_pipe_pending_count(uv_pipe_t* handle);
  uv_handle_type uv_pipe_pending_type(uv_pipe_t* handle);
  int uv_pipe_chmod(uv_pipe_t* handle, int flags);
]]

local Pipe = setmetatable({}, {__index = Stream})
Pipe.type = ffi.typeof 'uv_pipe_t'

function Loop:newPipe(ipc)
  local pipe = Pipe.type()
  uvCheck(UV.uv_pipe_init(self, pipe, ipc and 1 or 0))
  return pipe
end

function Pipe:open(fd)
  uvCheck(UV.uv_pipe_open(self, fd))
end

function Pipe:bind(path)
  uvCheck(UV.uv_pipe_bind(self, path))
end

-- TODO: add more pipe functions

ffi.metatype(Pipe.type, {__index = Pipe})

-------------------------------------------------------------------------------
-- Timer
-------------------------------------------------------------------------------

ffi.cdef [[
  typedef void (*uv_timer_cb)(uv_timer_t* handle);

  int uv_timer_init(uv_loop_t* loop, uv_timer_t* handle);
  int uv_timer_start(uv_timer_t* handle, uv_timer_cb cb, uint64_t timeout, uint64_t repeat);
  int uv_timer_stop(uv_timer_t* handle);
  int uv_timer_again(uv_timer_t* handle);
  void uv_timer_set_repeat(uv_timer_t* handle, uint64_t repeat);
  uint64_t uv_timer_get_repeat(const uv_timer_t* handle);
]]

local Timer = setmetatable({}, {__index = Handle})
Timer.Type = ffi.typeof 'uv_timer_t'

function Loop:newTimer()
  local timer = Timer.Type()
  uvCheck(UV.uv_timer_init(self, timer))
  return timer
end

function Timer:sleep(timeout)
  uvCheck(UV.uv_timer_start(self, makeCallback 'uv_timer_cb', timeout, 0))
  coroutine.yield()
  uvCheck(UV.uv_timer_stop(self))
end

function Timer:start(callback, timeout, rep)
  local cb = cast('uv_timer_cb', timeout)
  uvCheck(UV.uv_timer_start(self, callback, cb, rep))
  return cb
end

function Timer:stop()
  uvCheck(UV.uv_timer_stop(self))
end

function Timer:again()
  uvCheck(UV.uv_timer_again(self))
end

function Timer:setRepeat(rep)
  uvCheck(UV.uv_timer_set_repeat(self, rep))
end

function Timer:getRepeat()
  return UV.uv_timer_get_repeat(self)
end

local function onGc(handle)
  if not handle:isClosing() then
    -- We can't safely close handles here because onClose happens after the
    -- struct is freed by lua.
    -- Instead abort the process so the programmer can fix it early.
    handle = cast('uv_' .. Handle.getType(handle) .. '_t*', handle)
    error('Unclosed ' .. tostring(handle) .. ' got garbage collected')
  end
end

ffi.metatype(Timer.Type, {__index = Timer, __gc = onGc})

-------------------------------------------------------------------------------
-- Loop
-------------------------------------------------------------------------------

ffi.cdef [[
  uv_loop_t* uv_default_loop();
  int uv_loop_init(uv_loop_t* loop);
  int uv_loop_close(uv_loop_t* loop);
  int uv_loop_alive(const uv_loop_t* loop);
  void uv_stop(uv_loop_t* loop);
  uint64_t uv_now(const uv_loop_t* loop);
  void uv_update_time(uv_loop_t* loop);
  void uv_walk(uv_loop_t* loop, uv_walk_cb walk_cb, void* arg);
  int uv_run(uv_loop_t* loop, uv_run_mode mode);
]]

local LoopType = ffi.typeof 'uv_loop_t'

function Loop.new()
  local loop = LoopType()
  uvCheck(UV.uv_loop_init(loop))
  return loop
end

function Loop:close()
  uvCheck(UV.uv_loop_close(self))
end

function Loop:alive()
  return UV.uv_loop_alive(self) ~= 0
end

function Loop:stop()
  return UV.uv_loop_stop(self)
end

function Loop:now()
  return UV.uv_loop_now(self)
end

function Loop:updateTime()
  return UV.uv_update_time(self)
end

function Loop:walk(callback)
  local function onHandle(handle)
    callback(cast('uv_' .. Handle.getType(handle) .. '_t*', handle))
  end
  local cb = cast('uv_walk_cb', onHandle)
  UV.uv_walk(self, cb, nil)
  cb:free()
end

function Loop:run(mode)
  mode = assert(UV['UV_RUN_' .. string.upper(mode)], 'Unknown run mode')
  return tonumber(uvCheck(UV.uv_run(self, mode)))
end

ffi.metatype(LoopType, {__index = Loop})

-------------------------------------------------------------------------------

Loop.Req = Req
Loop.Connect = Connect
Loop.Write = Write
Loop.Shutdown = Shutdown
Loop.Handle = Handle
Loop.Stream = Stream
Loop.Tcp = Tcp
Loop.Timer = Timer

return UV.uv_default_loop()
