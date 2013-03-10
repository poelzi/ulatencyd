--[[
    Copyright 2010,2011 ulatencyd developers

    This file is part of ulatencyd.

    License: GNU General Public License 3 or later
]]--

XfceUI = {
  name = "XfceUI",
  re_basename = "xfwm4|xfce4-panel|xfdesktop",
  check = function(self, proc)
    local flag = ulatency.new_flag({name="user.ui", inherit=true})
    proc:add_flag(flag)
    proc:set_oom_score(-300)
    rv = ulatency.filter_rv(ulatency.FILTER_STOP)
    return rv
  end
}


XfceCore = {
  name = "XfceCore",
  re_basename = "xfce4-session",
    -- adjust the oom score adjust so x server will more likely survive
  check = function(self, proc)
    proc:set_oom_score(-300)

    return ulatency.filter_rv(ulatency.FILTER_STOP)
  end
}

-- gnome does a very bad job in setting grpid's, causing the complete
-- desktop to be run under one group. we fix this problem here, ugly
-- but working

-- filter that instantly sets a fake group on newly spawned processes from
-- gnome-panel or x-session-manager


XfceFix = RunnerFix.new("XfceFix", {"x-session-manager", "xfce4-session"})

-- on start we have to fix all processes that have descented from session manager/panel
local function cleanup_xfce_mess()
  cleanup_desktop_mess({"x-session-manager", "xfce4-session"})
  return false
end

ulatency.add_timeout(cleanup_xfce_mess, 1000)

ulatency.register_filter(XfceCore)
ulatency.register_filter(XfceUI)
ulatency.register_filter(XfceFix)
