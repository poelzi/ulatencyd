--[[
    Copyright 2010,2011 ulatencyd developers

    This file is part of ulatencyd.

    License: GNU General Public License 3 or later
]]--

GnomeUI = {
  name = "GnomeUI",
  re_basename = "metacity|compiz|gnome-panel|gtk-window-decorator|nautilus",
  --re_basename = "metacity",
  check = function(self, proc)
    local flag = ulatency.new_flag("user.ui")
    proc:add_flag(flag)
    proc:set_oom_score(-300)
    rv = ulatency.filter_rv(ulatency.FILTER_STOP)
    return rv
  end
}


GnomeCore = {
  name = "GnomeCore",
  re_basename = "x-session-manager",
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


GnomeFix = RunnerFix.new("GnomeFix", {"gnome-panel", "x-session-manager", "gnome-session"})

-- on start we have to fix all processes that have descented from kde
local function cleanup_gnome_mess()
  cleanup_desktop_mess({"x-session-manager", "gnome-session"})
  return false
end

ulatency.add_timeout(cleanup_gnome_mess, 1000)

ulatency.register_filter(GnomeCore)
ulatency.register_filter(GnomeUI)
ulatency.register_filter(GnomeFix)
