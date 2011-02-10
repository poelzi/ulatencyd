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
posix = require("posix")

-- monkey patching lua core

function string:split(sep)
        local sep, fields = sep or ":", {}
        local pattern = string.format("([^%s]+)", sep)
        self:gsub(pattern, function(c) fields[#fields+1] = c end)
        return fields
end

function table.copy(t)
  local t2 = {}
  for k,v in pairs(t) do
    t2[k] = v
  end
  return t2
end

function table.merge(t, t2)
  for k,v in pairs(t2) do
    t[k] = v
  end
  return t
end


-- logging shortcuts

function ulatency.log_trace(msg)
  ulatency.log(ulatency.LOG_LEVEL_TRACE, msg)
end

function ulatency.log_sched(msg)
  ulatency.log(ulatency.LOG_LEVEL_SCHED, msg)
end

function ulatency.log_debug(msg)
  ulatency.log(ulatency.LOG_LEVEL_DEBUG, msg)
end

function ulatency.log_info(msg)
  ulatency.log(ulatency.LOG_LEVEL_INFO, msg)
end

function ulatency.log_warning(msg)
  ulatency.log(ulatency.LOG_LEVEL_WARNING, msg)
end

function ulatency.log_error(msg)
  ulatency.log(ulatency.LOG_LEVEL_ERROR, msg)
end

function ulatency.log_critical(msg)
  ulatency.log(ulatency.LOG_LEVEL_CRITICAL, msg)
end

function re_from_table(tab)
  return table.concat(tab, "|")
end

function ulatency.list_processes_group(key)
  procs = ulatency.list_processes()
  rv = {}
  for i, proc in ipairs(procs) do
    c = rv[proc[key]]
    if not c then
      rv[proc[key]] = { proc }
    else
      c[#c+1] = proc
    end
  end
  return rv
end

function ulatency.add_adjust_flag(lst, match, adj)
   for i, flag in ipairs(lst) do
     for k, v in pairs(match) do
       if flag[k] ~= v then
         flag = nil
        break
      end
    end
    if flag then
      for k, v in pairs(adj) do
        flag[k] = v
      end
      return flag, true
    end
  end
  local flag = ulatency.new_flag(match)
  for k, v in pairs(adj) do
    flag[k] = v
  end
  return flag, false
end

function ulatency.find_flag(lst, match)
  for i, flag in ipairs(lst) do
    for k, v in pairs(match) do
      if flag[k] ~= v then
        flag = nil
        break
      end
    end
    if flag then
      return flag
    end
  end
end

-- load defaults.conf
if(not ulatency.load_rule("../cgroups.conf")) then
  if(not ulatency.load_rule("../conf/cgroups.conf")) then
    ulatency.log_error("can't load defaults.conf")
  end
end

-- build a list of usefull mountpoints
ulatency.mountpoints = {}

local function load_mountpoints()
  local fp = io.open("/proc/mounts")
  local good = { sysfs=true, debugfs=true }

  if not fp then
    ulatency.log_error("/proc/mounts could not be opened")
  end
  for line in fp:lines() do
    local chunks = string.split(line, " ")
    if good[chunks[3]] then
      ulatency.mountpoints[chunks[3]] = chunks[2]
    end
  end
  fp:close()
end
load_mountpoints()

if not ulatency.mountpoints["sysfs"] then
  ulatency.log_error("sysfs is not mounted")
end


local __CGROUP_HAS = false
local __CGROUP_AVAIL = false
local __CGROUP_LOADED = {}

function ulatency.tree_loaded(name)
  return __CGROUP_LOADED[name]
end


function ulatency.has_cgroup_subsystem(name)
  if not __CGROUP_HAS then
    ulatency.get_cgroup_subsystems()
  end
  return (__CGROUP_HAS[name] == true)
end


function ulatency.get_cgroup_subsystems()
  __CGROUP_AVAIL = {}
  __CGROUP_HAS = {}
  for line in io.lines("/proc/cgroups") do 
    if string.sub(line, 1, 2) ~= "#" then
      local var = string.gmatch(line, "(%w+)%s+.+")()
      __CGROUP_AVAIL[#__CGROUP_AVAIL+1] = var
      __CGROUP_HAS[var] = true
    end
  end
  return __CGROUP_AVAIL
end

-- reading / writing to /proc/sys

function ulatency.get_sysctl(name)
  local pname = string.gsub(name, "%.", "/")
  print("open".."/proc/sys/" .. pname)
  local fp = io.open("/proc/sys/" .. pname)
  if not fp then
    return nil
  end
  local data = fp:read("*a")
  fp:close()
  return data
end

function ulatency.set_sysctl(name, value)
  local pname = string.gsub(name, "%.", "/")
  local fp = io.open("/proc/sys/" .. pname, "w")
  if not fp then
    return false
  end
  fp:write(value)
  fp:close()
  return true
end

-- CGroups interface

if ulatency.get_uid() > 0 or 
   ulatency.get_config("logging", "disable_cgroup") == "true" then
  ulatency.log_info("disable cgroups error logging. not running as root")
  function cg_log(...)
  end
else
  cg_log = ulatency.log_warning
end



local function mkdirp(path)
  if posix.access(path) ~= 0 then
    local parts = path:split("/")
    for i,v in ipairs(parts) do
      name = "/" .. table.concat(parts, "/", 1, i)
      if posix.access(name, posix.R_OK) ~= 0 then
        if posix.mkdir(name) ~= 0 then
          cg_log("can't create "..name)
          return false
        end
      end
    end
  end
  return true
end



local _CGroup_Cache = {}

CGroup = {}

function CGroup_tostring(data, key)
  return "<CGroup ".. data.tree .. ":" .. data.name ..">"
end


function CGroup_index(data, key)
  print("index", data, key)

end


if string.sub(CGROUP_ROOT, -1) ~= "/" then
  CGROUP_ROOT = CGROUP_ROOT .. "/"
end

-- test if a cgroups is mounted
local function is_mounted(mnt_pnt)
  if string.sub(mnt_pnt, #mnt_pnt) == "/" then
    mnt_pnt = string.sub(mnt_pnt, 1, #mnt_pnt-1)
  end
  for line in io.lines("/proc/mounts") do
    if string.find(line, mnt_pnt) then
      return true
    end
  end
  return false
end

-- try mounting the mountpoints
if not is_mounted(CGROUP_ROOT) then
  -- try mounting a tmpfs there
  local prog = "/bin/mount -n -t tmpfs none "..CGROUP_ROOT.."/"
  ulatency.log_info("mount cgroups root: "..prog)
  fd = io.popen(prog, "r")
  print(fd:read("*a"))
  if not is_mounted(CGROUP_ROOT) then
    ulatency.log_error("can't mount: "..CGROUP_ROOT)
  end
end

-- disable the autogrouping
local fp = io.open("/proc/sys/kernel/sched_autogroup_enabled", "w")
if fp then
  ulatency.log_info("disable sched_autogroup in linux kernel")
  fp:write("0")
  fp:close()
end

ulatency.log_info("available cgroup subsystems: "..table.concat(ulatency.get_cgroup_subsystems(), ", "))

local __found_one_group = false
for n,v in pairs(CGROUP_MOUNTPOINTS) do
  local path = CGROUP_ROOT..n
  local mnt_opts = false
  for i, subsys in ipairs(v) do
    if ulatency.has_cgroup_subsystem(subsys) then
      if mnt_opts then
        mnt_opts = mnt_opts .. ","..subsys
      else
        mnt_opts = subsys
      end
    end
  end
  if mnt_opts then
    if is_mounted(path) then
      ulatency.log_info("mount point "..path.." is already mounted")
      __CGROUP_LOADED[n] = true
      __found_one_group = true
    else
      mkdirp(path)
      local prog = "/bin/mount -n -t cgroup -o "..mnt_opts.." none "..path.."/"
      ulatency.log_info("mount cgroups: "..prog)
      fd = io.popen(prog, "r")
      print(fd:read("*a"))
      if not is_mounted(path) then
        ulatency.log_error("can't mount: "..path)
      else
        __CGROUP_LOADED[n] = true
        __found_one_group = true
      end
    end
    local fp = io.open(path.."/release_agent", "r")
    local ragent = fp:read("*a")
    fp:close()
    -- we only write a release agent if not already one. update if it looks like
    -- a ulatencyd release agent
    if ragent == "" or ragent == "\n" or string.sub(ragent, -22) == '/ulatencyd_cleanup.lua' then
      local fp = io.open(path.."/release_agent", "w")
      if fp then
        fp:write(ulatency.release_agent)
        fp:close()
      end
    end
  else
    ulatency.log_info("no cgroups subsystem found for group "..n..". disable group")
  end
end

if not __found_one_group then
  ulatency.log_error("could not found one cgroup to mount.")
end
__found_one_group = nil

CGroupMeta = { __index = CGroup, __tostring = CGroup_tostring}

local function cgroups_cleanup()
  local to_remove = {}
  for n, c in pairs(_CGroup_Cache) do
    if c:can_be_removed() then
      to_remove[#to_remove + 1] = n
    end
  end
  for i,group in ipairs(to_remove) do
    local needed = false
    for i, test in ipairs(to_remove) do
      if string.sub(test, 1, #group) == group then
        needed = true
        break
      end
    end
    if not needed then
      _CGroup_Cache[group]:remove()
      _CGroup_Cache[group] = nil
    end
  end

  return true
end

ulatency.add_timeout(cgroups_cleanup, 120000)

function CGroup.new(name, init, tree)
  tree = tree or "cpu"
  rv = _CGroup_Cache[tree..'/'..name]
  if rv then
    return rv
  end
  if CGROUP_DEFAULT[tree] then
    cinit = table.copy(CGROUP_DEFAULT[tree])
  else
    cinit = {}
  end
  uncommited=table.merge(cinit, init or {})
  rv = setmetatable( {name=name, uncommited=uncommited, new_tasks={},
                      tree=tree, adjust={}, used=false}, CGroupMeta)
  _CGroup_Cache[tree..'/'..name] = rv
  return rv
end

function CGroup.get_groups()
  return _CGroup_Cache
end

function CGroup.get_group(name)
  return _CGroup_Cache[name]
end


function CGroup:path(file)
  if file then
    return CGROUP_ROOT .. self.tree .. "/".. self.name .. "/" .. tostring(file)
  else
    return CGROUP_ROOT .. self.tree .. "/" .. self.name
  end
end

function CGroup:path_parts()
  return self.name:split("/")
end

function CGroup:parent()
  parts = self.name:split("/")
  name = table.concat(parts, "/", 1, #parts-1)
  if _CGroup_Cache[name] then
    return _CGroup_Cache[name]
  end
  return CGroup.new(name)
end

function CGroup:get_value(key, raw)
  uncommited = rawget(self, "uncommited")
  if uncommited[key] and not raw then
    return uncommited[key]
  end
  local path = self:path(key)
  if posix.access(path) == 0 then
    local fp = io.open(path, "r")
    return fp:read("*a")
  end
end


function CGroup:set_value(key, value)
  uncommited = rawget(self, "uncommited")
  uncommited[key] = value
end

function CGroup:get_tasks()
  local t_file = self:path("tasks")
  if posix.access(t_file, posix.R_OK) ~= 0 then
    return {}
  end
  rv = {}
  for line in io.lines(t_file) do
    rv[#rv+1] = tonumber(line)
  end
  return rv
end

function CGroup:has_tasks()
  local rv = false
  local t_file = self:path("tasks")
  if posix.access(t_file, posix.R_OK) ~= 0 then
    return false
  end
  for line in io.lines(t_file) do
      rv = true
      break
  end
  return rv
end


function CGroup:run_adjust(proc)
  adjust = rawget(self, "adjust")
  for i,v in ipairs(adjust) do
    v(self, proc)
  end
end

--function CGroup:adjust()
--  return rawget(self, "adjust")
--end


function CGroup:add_task(pid, instant)
  nt = rawget(self, "new_tasks")
  if not nt then
    nt = {}
    rawset(self, "new_tasks", nt)
  end
  nt[#nt+1] = pid
  --pprint(nt)
  if instant then
    --print("instant")
    local t_file = self:path("tasks")
    fp = io.open(t_file, "w")
    --print(t_file)
    if fp then
      fp:write(tostring(pid))
    --  print("write")
      ulatency.log_sched("Move "..pid.." to "..tostring(self))
      fp:close()
    else
      cg_log("can't attach "..pid.." to group "..t_file)
    end
  end
end

function CGroup:is_dirty()
  if #rawget(self, "uncommited") > 0 or
     #rawget(self, "new_tasks") > 0 or 
     posix.access(self:path()) ~= 0 then
     return true
  end
  return false
end

function CGroup:exists()
  if posix.access(self:path()) == 0 then
    return true
  end
  if #rawget(self, "uncommited") > 0 or
     #rawget(self, "new_tasks") > 0 then
     return true
  end
  return false
end

function CGroup:can_be_removed()
  if self:has_tasks() or #rawget(self, "new_tasks") > 0 then
    return false
  end
  return true
end

function CGroup:remove()
  posix.rmdir(self:path())
end


function CGroup:commit()
  mkdirp(self:path())
  local uncommited = rawget(self, "uncommited")
  for k, v in pairs(uncommited) do
    local par = string.sub(k, 1, 1)
    if par == '?' then
      k = string.sub(k, 2)
    else
      par = nil
    end
    local path = self:path(k)
    local fp = io.open(path, "w")
    if fp then
      --print("write"..path)
      fp:write(v)
      fp:close()
      uncommited[k] = nil
    else
      if par ~= '?' then
        cg_log("can't write into :"..tostring(path))
      end
    end
  end
  local t_file = self:path("tasks")
  local fp = io.open(t_file, "w")
  if fp then
    local pids = rawget(self, "new_tasks")
    if pids then
      while true do
        pid = table.remove(pids, 1)
        if not pid then
          break
        end
        fp:write(pid)
        ulatency.log_sched("Move "..pid.." to "..tostring(self))
      end
      fp:close()
    end
  end
end

function CGroup:add_children(proc, fnc)
  function add_childs(list)
    for i,v in pairs(list) do
      self:add_task(v.pid)
      if fnc then
        fnc(v)
      end
    end
    for i,v in pairs(list) do
      add_childs(v.children)
    end
  end
  add_childs(proc.children)
end

function CGroup.create_isolation_group(proc, children)
  ng = CGroup.new("iso_"..tostring(pid))
  ng.commit()
  ng.add_task(proc.pid)
  proc:set_block_scheduler(1)
  if children then
    ng:add_children(proc, true)
  end
end

function CGroup:starve(what)
  if what == "memory" then
    nv = self:get_value("memory.usage_in_bytes", true)
    if nv then
      self:set_value("memory.limit_in_bytes", nv)
    end
  end
end





-- helper classes

function to_string(data, indent)
    local str = ""

    if(indent == nil) then
        indent = 0
    end

    -- Check the type
    if(type(data) == "string") then
        str = str .. (" "):rep(indent) .. data .. "\n"
    elseif(type(data) == "number") then
        str = str .. (" "):rep(indent) .. data .. "\n"
    elseif(type(data) == "boolean") then
        if(data == true) then
            str = str .. "true"
        else
            str = str .. "false"
        end
    elseif(type(data) == "table") then
        local i, v
        for i, v in pairs(data) do
            -- Check for a table in a table
            if(type(v) == "table") then
                str = str .. (" "):rep(indent) .. i .. ":\n"
                str = str .. to_string(v, indent + 2)
            else
                str = str .. (" "):rep(indent) .. i .. ": " .. to_string(v, 0)
            end
        end
    else
        return tostring(data).."\n"
    end

    return str
end

function pprint(data)
  print(to_string(data))
end
