-- Buffered reader
--

Buffered = {transport = nil, buffer = nil, pos = nil}
function Buffered:new(t)
  o = {transport = t, buffer = t:read(8192), pos = 1}
  setmetatable(o, self)
  self.__index = self
  return o 
end

function Buffered:lines()
  return self.readline, self
end

function Buffered:readline()
  local chunks = {}
  while (self.buffer) do
    local s, e = string.find(self.buffer, "[^\r\n]*\r\n", self.pos)
    if s then
      self.pos = e + 1
      table.insert(chunks, string.sub(self.buffer, s, e-2))
      local line = table.concat(chunks) 
      chunks = nil
      return line
    else
      table.insert(chunks, string.sub(self.buffer, self.pos))
      self.buffer = self.transport:read(8192)
      self.pos = 1
    end
  end
  return nil
end

function Buffered:readblock(len)
  local rest_len = string.len(self.buffer) - self.pos + 1
  if (len == 0) then
    return ""
  end
  if (len <= rest_len) then
    local block = string.sub(self.buffer, self.pos, self.pos + len - 1)
    self.pos = self.pos + len
    return block
  end
  local chunks = {}
  local real_len = len - rest_len
  table.insert(chunks, string.sub(self.buffer, self.pos))
  while real_len > 0 do
    self.buffer = self.transport:read(real_len)
    real_len = real_len - string.len(self.buffer)
    table.insert(chunks, self.buffer)
  end
  local block = table.concat(chunks)
  chunks = nil
  return block
end

function Buffered:readeof()
  local chunks = {}
  while (self.buffer) do
    table.insert(chunks, string.sub(self.buffer, self.pos))
    self.pos = 1
    self.buffer = self.transport:read(8192)
  end
  local block = table.concat(chunks)
  chunks = nil
  return block
end

