-----------------------------------------------------------------------------
-- Licensed to the Apache Software Foundation (ASF) under one or more
-- contributor license agreements. 
-- The ASF licenses this file to You under the Apache License, Version 2.0
-- (the "License"); you may not use this file except in compliance with
-- the License.  You may obtain a copy of the License at
--     http://www.apache.org/licenses/LICENSE-2.0
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.
-----------------------------------------------------------------------------
-- HTTP Class
-- by christian liesch <liesch@gmx.ch>
-----------------------------------------------------------------------------
 
HTTP = {buffered = nil, headers = nil}

-- Constructor
-- @param b IN buffered object
-- @return buffered object
function HTTP:new(b)
  o = {buffered = b, headers = {mt = {}, values = {}}}
  setmetatable(o, self)
  self.__index = self
  -- keys of headers are case-insensitiv
  setmetatable(o.headers, o.headers.mt)
  o.headers.mt.__index = function(t, key)
    return t.values[string.lower(key)]
  end
  o.headers.mt.__newindex = function(t, key, value)
    t.values[string.lower(key)] = value
  end
  return o 
end

-- Read all headers but no body
-- @return status, headers
function HTTP:readheaders()
  local status = self.buffered:readline()
  for line in self.buffered:lines() do
    if (string.len(line) == 0) then
      break;
    end
    name, value = string.match(line, "([^:]*): (.*)") 
    self.headers[name] = value
  end
  return status, self.headers
end

-- Read body
-- @return body
function HTTP:readbody()
  if (self.headers and self.headers["Content-Length"]) then
    local len = self.headers["Content-Length"]
    return self.buffered:readblock(len)
  end
  return nil
end

-- Read hole request
-- @return status, headers, body
function HTTP:read()
  return self.readheaders(), self.readbody()
end

