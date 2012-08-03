--[[
    Copyright 2010,2011 ulatencyd developers

    This file is part of ulatencyd.

    License: GNU General Public License 3 or later

    common code for fixing bad behaviour of desktop uis
]]--

-- search if name is in table lst
function in_list(name, lst)
  for i,v in ipairs(lst) do
    if name == v then
      return true
    end
  end
  return false
end


--[[ 
UIRunnerFix class

this allows easy defination of bad behaving starters that are supposed to 
change the process group of it's children
]]--

RunnerFix = {}

function RunnerFix:check(proc)
  -- remove old blacklist items
  if in_list(proc.cmdfile, self.bad_starters) and
     proc.pgrp == proc.pid then   -- matches bad_starters themselves
    -- we save two blacklists, the pgrp blacklist and the pid blacklist
    -- so we can lookup very fast if we should change a pgrp
    self.blacklist_pgrp[proc.pgrp] = proc.pid
    self.blacklist_pid[proc.pid] = proc.pgrp
  end
  parent = proc:get_parent()
  if parent then
    -- dettach direct children of bad_startes to separate process groups
    if in_list(parent.cmdfile, self.bad_starters) then
      proc:set_pgid(proc.pid)
    -- dettach bad_starters from init to separate process groups
    elseif ( parent.pid == 1 and self.blacklist_pgrp[proc.pgrp] ) or 
           ( in_list(parent.cmdfile, self.bad_starters) and self.blacklist_pgrp[proc.pgrp] ) -- WTF? This never matches, condition is same as previous IF condition.
      then
      proc:set_pgid(proc.pid)
    end
  end
  return ulatency.filter_rv(ulatency.FILTER_STOP)
end

function RunnerFix:exit(proc)
  if self.blacklist_pid[proc.pid] then
    self.blacklist_pgrp[self.blacklist_pid[proc.pid]] = nil
    self.blacklist_pid[proc.pid] = nil
  end
end

local function RunnerFix_tostring(data)
  return "<UIRunnerFix "..data.name..">"
end
local RunnerFixMeta = { __index = RunnerFix, __tostring = RunnerFix_tostring}

  --re_basename = "metacity",
function RunnerFix.new(name, bad_starters)
  return setmetatable({ name=name, bad_starters=bad_starters,
                        blacklist_pgrp={}, blacklist_pid={},
                      }, 
                      RunnerFixMeta)
end





-- on start we have to fix all processes that have descented from a group
-- of programs
function cleanup_desktop_mess(bad_starters)
  local procs = ulatency.list_processes()
  local init = ulatency.get_pid(1)
  local remap = {}
  -- we search for bad starters first and save their pgrp
  for i,proc in ipairs(procs) do
    if in_list(proc.cmdfile, bad_starters) then
      remap[#remap+1] = proc.pgrp
      -- fix all children of these bad starters
      for i,child in ipairs(proc:get_children()) do
        child:set_pgid(child.pid)
      end
    end
  end
  -- we now search for detached processes which may now belong to init
  -- only change the top level entries. the fix will travel down as long as 
  -- needed. this may take some iterations, thou
  for i,proc in ipairs(init:get_children()) do
    for i,map in ipairs(remap) do
      if not in_list(proc.cmdfile, bad_starters) then
        if proc.pgrp == map then
          proc:set_pgid(proc.pid)
        end
      end
    end
  end
  return false
end

