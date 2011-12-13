-----------------------------------------------------------------------------------------
-- LUA only HtmlParser from Christian Liesch based on Alexander Makeev's XmlParser
-- Dec. 2011
-----------------------------------------------------------------------------------------

HtmlParser = {};

-- Set implementation
-- @param list IN list of Set elements
-- @return a set of keys with value true
function Set(list)
  local set = {}
  for _, l in ipairs(list) do
    set[l] = true
  end
  return set
end

-- Do a subset of html conversions
-- @param value IN HTML string
-- @return resolved HTML string
function HtmlParser:FromHtmlString(value)
        value = string.gsub(value, "&#x([%x]+)%;",
        function(h) 
                return string.char(tonumber(h,16)) 
        end);
        value = string.gsub(value, "&#([0-9]+)%;",
        function(h) 
                return string.char(tonumber(h,10)) 
        end);
        value = string.gsub (value, "&quot;", "\"");
        value = string.gsub (value, "&apos;", "'");
        value = string.gsub (value, "&gt;", ">");
        value = string.gsub (value, "&lt;", "<");
        value = string.gsub (value, "&amp;", "&");
        return value;
end
   
-- Parse args in a tag
-- @param args IN args string
-- @return table of arguments
function HtmlParser:ParseArgs(args)
  local arg = {}
  string.gsub(args, "(%w+)=([\"'])(.-)%2", 
              function (w, _, a)
                arg[w] = self:FromHtmlString(a);
              end)
  return arg
end

-- HTML parser itself
-- @param htmlText IN the html text to parse
-- @return a tree of html nodes
function HtmlParser:ParseHtmlText(htmlText)
  local emptySet = Set{ "br", "hr" }
  local stack = {}
  local top = { Name = nil, Value = nil, Attributes = {}, ChildNodes = {} }
  table.insert(stack, top)
  local ni, close, label, xarg, empty
  local i, j = 1, 1

  while true do
    ni, j, close, label, xarg, empty = string.find(htmlText, "<(%/?)([%w:]+)(.-)(%/?)>", i)
    if not ni then break end
    local text = string.sub(htmlText, i, ni-1);
    if not string.find(text, "^%s*$") then
      top.Value = (top.Value or "")..self:FromHtmlString(text);
    end

    if emptySet[label] or empty == "/" then
      table.insert(top.ChildNodes, { Name = label, Value = nil, Attributes = self:ParseArgs(xarg), ChildNodes = {}})
    elseif close == "" then
      top = { Name = label, Value = nil, Attributes = self:ParseArgs(xarg), ChildNodes = {} }
      table.insert(stack, top)
    else 
      local toclose = table.remove(stack)
      top = stack[#stack]
      if #stack < 1 then
        break;
      elseif toclose.Name ~= label then
        local tmp = {}
        table.insert(tmp, toclose)
        while toclose.Name ~= label do
          toclose = table.remove(stack)
          if toclose.Name ~= label then
            table.insert(tmp, toclose)
          end 
        end
        for i = 1,#tmp do
          table.insert(toclose.ChildNodes, tmp[i])
        end
        top = stack[#stack]
        table.insert(top.ChildNodes, toclose)
      else
        table.insert(top.ChildNodes, toclose)
      end
    end

    i = j + 1
  end

  local text = string.sub(htmlText, i);
  if not string.find(text, "^%s*$") then
      stack[#stack].Value = (stack[#stack].Value or "")..self:FromHtmlString(text);
  end

  return stack[1].ChildNodes[1];
end

------------------------------------------------------------------------------------------

function log(str)
  print(str)
end

function dump(_class, no_func, depth)
        if(not _class) then 
                log("nil");
                return;
        end
        
        if(depth==nil) then depth=0; end
        local str="";
        for n=0,depth,1 do
                str=str.."\t";
        end
    
        log(str.."["..type(_class).."]");
        log(str.."{");
    
        for i,field in pairs(_class) do
                if(type(field)=="table") then
                        log(str.."\t"..tostring(i).." =");
                        dump(field, no_func, depth+1);
                else 
                        if(type(field)=="number") then
                                log(str.."\t"..tostring(i).."="..field);
                        elseif(type(field) == "string") then
                                log(str.."\t"..tostring(i).."=".."\""..field.."\"");
                        elseif(type(field) == "boolean") then
                                log(str.."\t"..tostring(i).."=".."\""..tostring(field).."\"");
                        else
                                if(not no_func)then
                                        if(type(field)=="function")then
                                                log(str.."\t"..tostring(i).."()");
                                        else
                                                log(str.."\t"..tostring(i).."<userdata=["..type(field).."]>");
                                        end
                                end
                        end
                end
        end
        log(str.."}");
end

local htmlTree = HtmlParser:ParseHtmlText([[
<html>
  <head>
    <meta foo="bar1">
    <meta foo="bar2">
    <meta foo="bar3">
  </head>
  <body>
  <table>
    <tr>
      bla
    </tr>
  </table>
  <img href=foo.bar.ch/bla alt=blabla>
  </body>
</html>
]])
dump(htmlTree)

function HtmlParser:GetTag(htmlTree, path)
  for tag in string.gmatch(path, "([^\.]+)\.?") do
    print(tag)
  end
end

-- Much better would be:
-- html.head.meta[1].foo
HtmlParser:GetTag(htmlTree, "html.head.meta[1].foo")

