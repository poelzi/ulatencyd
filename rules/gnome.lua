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

-- gnome does a very bad job in setting grpid's, causing the complete
-- desktop to be run under one group. we fix this problem here, ugly
-- but working

-- filter that instantly sets a fake group on newly spawned processes from
-- gnome-panel or x-session-manager
GnomeFix = {
  name = "GnomeFix",
  --re_basename = "metacity",
  check = function(self, proc)
    parent = proc:get_parent()
    if parent then
      if parent.cmdfile == "gnome-panel" or
         parent.cmdfile == "x-session-manager" then
        proc:set_pgid(proc.pid)
      end
    end
    rv = ulatency.filter_rv(ulatency.FILTER_STOP)
    return rv
  end
}

-- on start we have to fix all processes that have descented from kde
local function cleanup_gnome_mess()
  local procs = ulatency.list_processes()
  local init = ulatency.get_pid(1)
  local remap = {}
  for i,proc in ipairs(procs) do
    if proc.cmdfile == "x-session-manager" then
      remap[#remap+1] = proc.pgrp
      for i,child in ipairs(proc:get_children()) do
        child:set_pgid(child.pid)
      end
    end
  end
  for i,proc in ipairs(init:get_children()) do
    for i,map in ipairs(remap) do
      if proc.cmdfile ~= "x-session-manager"then
        if proc.pgrp == map then
          proc:set_pgid(proc.pid)
        end
      end
    end
  end
  return false
end

ulatency.add_timeout(cleanup_gnome_mess, 1000)

ulatency.register_filter(GnomeUI)
ulatency.register_filter(GnomeFix)
