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
--! @brief extending lua type `table`
-------------------------------------------------------------------------------


--! @addtogroup lua_EXT
--! @{

--! @brief copies tables
--! @param t table
--! @return new table with shallow copy
function table.copy(t)
  local t2 = {}
  for k,v in pairs(t) do
    t2[k] = v
  end
  return t2
end


--! @brief merge two tables
--! @param t table of source 1
--! @param t2 table of source 2
--! @return table t
function table.merge(t, t2)
  for k,v in pairs(t2) do
    t[k] = v
  end
  return t
end

--! @} End of "addtogroup lua_EXT"