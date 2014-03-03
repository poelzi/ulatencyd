--[[
    Copyright 2010,2011 ulatencyd developers

    This file is part of ulatencyd.

    ulatencyd is free software: you can redistribute it and/or modify it under 
    the terms of the GNU General Public License as published by the 
    Free Software Foundation, either version 3 of the License, 
    or (at your option) any later version.

    ulatencyd is distributed in the hope that it will be useful, 
    but WITHOUT ANY WARRANTY; without even the implied warranty of 
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
    See the GNU General Public License for more details.

    You should have received a copy of the GNU General Public License 
    along with ulatencyd. If not, see http://www.gnu.org/licenses/.
]]--

-------------------------------------------------------------------------------
--! @file
--! @ingroup lua_EXT
--! @brief extending lua type `string`
-------------------------------------------------------------------------------


--! @addtogroup lua_EXT
--! @{

--! @brief split string with seperator sep
--! @param sep seperator
--! @return new table with chunks
function string:split(sep)
        local sep, fields = sep or ":", {}
        local pattern = string.format("([^%s]+)", sep)
        self:gsub(pattern, function(c) fields[#fields+1] = c end)
        return fields
end

--! @brief remove trailing whitespace from string.
--! http://en.wikipedia.org/wiki/Trim_(8programming)
function string:rtrim()
  local n = #self
  while n > 0 and self:find("^%s", n) do n = n - 1 end
  return self:sub(1, n)
end

--! @} End of "addtogroup lua_EXT"