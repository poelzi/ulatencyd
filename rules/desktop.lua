--[[
    Copyright 2010,2011 ulatencyd developers

    This file is part of ulatencyd.

    License: GNU General Public License 3 or later
]]--


DesktopEssential = {
  name = "DesktopEssential",
  re_cmdline = "/usr/bin/X",
  check = function(self, proc)
    local flag = ulatency.new_flag{name="system.essential"}
    proc:add_flag(flag)
    -- adjust the oom score adjust so x server will more likely survive
    proc:set_oom_score(-400)

    rv = ulatency.filter_rv(ulatency.FILTER_STOP)
    return rv
  end
}


ulatency.register_filter(DesktopEssential)
