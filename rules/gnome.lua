--[[
    Copyright 2010,2011 ulatencyd developers

    This file is part of ulatencyd.

    License: GNU General Public License 3 or later
]]--

GnomeUI = {
  name = "GnomeUI",
  re_basename = "metacity|compiz|gnome-panel|gtk-window-deco",
  --re_basename = "metacity",
  check = function(self, proc)
    local flag = ulatency.new_flag("user.ui")
    proc:add_flag(flag)

    rv = ulatency.filter_rv(ulatency.FILTER_STOP)
    return rv
  end
}

ulatency.register_filter(GnomeUI)
