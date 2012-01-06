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
-- Websockets Class
-- by christian liesch <liesch@gmx.ch>
-----------------------------------------------------------------------------
 
Websocket = {buffered = nil}

-- Constructor
-- @param b IN buffered object
-- @return buffered object
function Websocket:new(b)
  o = {buffered = b}
  setmetatable(o, self)
  self.__index = self
  return o 
end

function HTTP:read()
  opcode = self.buffered:readblock(1);
  payloadLen = self.buffered:readblock(1);
  if string.byte(payloadLen) == 126 then
    payloadLen = self.buffered:readblock(2)
  elseif string.byte(payloadLen) == 127 then
    payloadLen = self.buffered:readblock(4)
  end
  self.buffered:readblock(payloadLen)
end

function HTTP:write(obcode, len, bytes)
  if len < 126 then
    self.buffered.transport:send(0, 1)
    self.buffered.transport:send(len)
    self.buffered.transport:send(bytes, len)
  end
end

