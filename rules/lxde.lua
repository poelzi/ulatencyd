--[[
    Copyright 2010,2011 ulatencyd developers

    This file is part of ulatencyd.

    License: GNU General Public License 3 or later
]]--

LxdeRunnerFix = RunnerFix.new("LxdeRunnerFix", {"lxsession"})

-- on start we have to fix all processes that have descented from kde

local function cleanup_lxde_mess()
  cleanup_desktop_mess({"lxsession"})
  return false
end

ulatency.add_timeout(cleanup_lxde_mess, 1000)
ulatency.register_filter(LxdeRunnerFix)


