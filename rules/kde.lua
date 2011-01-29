--[[
    Copyright 2010,2011 ulatencyd developers

    This file is part of ulatencyd.

    License: GNU General Public License 3 or later
]]--

local Kde_Ui_Tab = {
  "kuiserver",
  "kwalletmanager",
  "knotify4",
  "kmix",
  "kded4",
  "kwin",
  "plasma",
  "plasma-desktop"
}


KdeUI = {
  name = "KdeUI",
  re_basename = re_from_table(Kde_Ui_Tab),
  --re_basename = "metacity",
  check = function(self, proc)
    local flag = ulatency.new_flag{name="user.ui"}
    proc:add_flag(flag)

    rv = ulatency.filter_rv(ulatency.FILTER_STOP)
    return rv
  end
}


-- kde does a very bad job in setting grpid's, causing the complete
-- desktop to be run under one group. we fix this problem here, ugly
-- but working

-- filter that instantly sets a fake group on newly spawned processes from
-- krunner und kdeinit4
KdeRunnerFix = {
  name = "KdeRunnerFix",
  --re_basename = "metacity",
  check = function(self, proc)
    parent = proc:get_parent()
    if parent then
      if parent.cmd == "krunner" or 
         parent.cmd == "kdeinit4" then
        proc:set_pgid(proc.pid)
      end
    end
    rv = ulatency.filter_rv(ulatency.FILTER_STOP)
    return rv
  end
}

-- on start we have to fix all processes that have descented from kde
local function cleanup_kde_mess()
  local procs = ulatency.list_processes()
  local init = ulatency.get_pid(1)
  local remap = {}
  for i,proc in ipairs(procs) do
    if proc.cmd == "kdeinit4" or proc.cmd == "krunner" then
      remap[#remap+1] = proc.pgrp
      for i,child in ipairs(proc:get_children()) do
        child:set_pgid(child.pid)
      end
    end
  end
  for i,proc in ipairs(init:get_children()) do
    for i,map in ipairs(remap) do
      if proc.cmd ~= "kdeinit4" and proc.cmd ~= "krunner" then
        if proc.pgrp == map then
          proc:set_pgid(proc.pid)
        end
      end
    end
  end
  return false
end

ulatency.add_timeout(cleanup_kde_mess, 1000)
ulatency.register_filter(KdeUI)
ulatency.register_filter(KdeRunnerFix)

