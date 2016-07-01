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
--! @ingroup lua_CORE
--! @brief extending `U_PROC`
-------------------------------------------------------------------------------


--! @brief Recursively applies the function to #U_PROC and its children.
--! @param fnc A function to apply. It will be called with #U_PROC passed recursively on the #U_PROC and all its
--! children.
--! @public @memberof U_PROC
function U_PROC:apply(fnc)
  local function adjust(list)
    for _,p in ipairs(list) do
      adjust(p:get_children())
      fnc(p)
    end
  end
  adjust(self:get_children())
  fnc(self)
end
