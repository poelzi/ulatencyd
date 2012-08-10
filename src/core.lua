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

---------------------------------
--! @file
--! @ingroup lua_CORE
--! @brief ulatencyd core lua library
---------------------------------

posix = require("posix")

--! @addtogroup lua_EXT
--! @{

--! @brief split string with seperator sep
--! @param sep seperator
--! @return new table with chunks
function string:split(sep)
        local sep, fields = sep or ":", {}
        local pattern = string.format("([^%s]+)", sep)
        self:gsub(pattern, function(c) fields[#fields+1] = c end)
        return fields
end

--! @brief copies tables
--! @param t table
--! @return new table with shallow copy
function table.copy(t)
  local t2 = {}
  for k,v in pairs(t) do
    t2[k] = v
  end
  return t2
end


--! @brief merge two tables
--! @param t table of source 1
--! @param t2 table of source 2
--! @return table t
function table.merge(t, t2)
  for k,v in pairs(t2) do
    t[k] = v
  end
  return t
end

--! @} End of "addtogroup lua_EXT"

--! @addtogroup lua_HELPERS
--! @{

--! @brief Recursively creates a directory.
--! @param path Full path of the new directory.
--! @return boolean
--! @retval TRUE if the directory was successfully created.
--! @retval FALSE if creation of some directory along the `path` failed.
function mkdirp(path)
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

--! @brief Log error after writing to sysfs failed: decides whether the error should be logged,
--! the log level and composes the error message.
--! @param filepath The file full path
--! @param value A value that trigger the error
--! @param err Textual representation of the error
--! @param err_code The error code (a number)
local function sysfs_write_error(filepath, value, err, err_code)

  local s,e = string.find(filepath, CGROUP_ROOT, 1, true)
  if s == 1 then

    -- error while writing to a cgroup subsystem
    local fields = string.split(string.sub(filepath, e+1), '/')
    if #fields >= 2 then
      local subsys = fields[1]
      local file = fields[#fields]
      local cgr_name = #fields >= 3 and table.concat(fields, '/', 2, #fields-1) or ""
      local cgr = CGroup.get_group(subsys ..'/'.. cgr_name)
      if cgr then
        -- error while adding task to a cgroup
        if file == "tasks" then
          -- no such process; ignore this error
          if err_code == 3 then
            return
          end
          -- error while moving rt task between cgroups in cpu subsystem on kernel without CONFIG_RT_GROUP_SCHED
          if cgr.tree == "cpu" and err_code == 22 and posix.access(cgr:path("cpu.rt_runtime_us")) ~= 0 then
            local task = ulatency.get_tid(value)
            if task and (task.sched == ulatency.SCHED_RR or task.sched == ulatency.SCHED_FIFO) then
              ulatency.log_debug(string.format(
                "Task (tid: %s, RT sched.) couldn't be moved to %s (%d: %s) (probably kernel w/o CONFIG_RT_GROUP_SCHED)",
                tostring(value), tostring(cgr), err_code, err
              ))
              return
            end
          end
          -- other error
          ulatency.log_warning(
            string.format("Task (tid: %s) couldn't be moved to %s (%d: %s)", tostring(value), tostring(cgr), err_code, err))
          return
        end
      end
    end
  end

  ulatency.log_warning(string.format("can't write string '%s' into %s: (%d) %s",tostring(value),filepath,err_code,err))
end

--! @brief Write string to a file under SYSFS
local function sysfs_write(path, value, quiet)
  local ok, err, err_code = false, nil, nil
  local fp = io.open(path, "w")
  if fp then
    fp:setvbuf("no")
    ok, err, err_code = fp:write(value)
    if not ok and not quiet then
      sysfs_write_error(path, value, err, err_code)
    end
    fp:close()
  end

  return ok, err, err_code
end
--! @} End of "addtogroup lua_HELPERS"

--! @name logging shortcuts
--! @{

--! @public @memberof ulatency
function ulatency.log_trace(msg)
  ulatency.log(ulatency.LOG_LEVEL_TRACE, msg)
end
--! @public @memberof ulatency
function ulatency.log_sched(msg)
  ulatency.log(ulatency.LOG_LEVEL_SCHED, msg)
end
--! @public @memberof ulatency
function ulatency.log_debug(msg)
  ulatency.log(ulatency.LOG_LEVEL_DEBUG, msg)
end
--! @public @memberof ulatency
function ulatency.log_info(msg)
  ulatency.log(ulatency.LOG_LEVEL_INFO, msg)
end
--! @public @memberof ulatency
function ulatency.log_warning(msg)
  ulatency.log(ulatency.LOG_LEVEL_WARNING, msg)
end
--! @public @memberof ulatency
function ulatency.log_error(msg)
  ulatency.log(ulatency.LOG_LEVEL_ERROR, msg)
end
--! @public @memberof ulatency
function ulatency.log_critical(msg)
  ulatency.log(ulatency.LOG_LEVEL_CRITICAL, msg)
end
--! @} End of "logging shortcuts"

function re_from_table(tab)
  return table.concat(tab, "|")
end

--! @brief Quits the ulatencyd daemon with scheduler cleanup.
--! @param flag (optional) A flag you believe will cause the scheduler cleanup, or properties of such flag. This flag
--! will be added to the system flags if it already isn't there. Implicit flag is
--! `{name="suspend",reason="ulatency.quit"}`. The scheduler should check at least for @link __SYSTEM_FLAG_SUSPEND
--! `suspend`@endlink and @link __SYSTEM_FLAG_QUIT`quit`@endlink system flags.
--! @param instant (optional) If TRUE, the flag cleanup flag is not set, normal shutdown sequence is skipped and
--! the daemon will quit immediately (after the queue of pending events in the main event loop are dispatched).
--! See `Scheduler:_quit()` documentation describing the shutdown sequence.
--! @public @memberof ulatency
function ulatency.quit(flag, instant)
  if not instant then
    local flag_props = flag or { name = "suspend", reason = "ulatency.quit" }
    local added
    flag, added = ulatency.add_adjust_flag(ulatency.list_flags(), flag_props, {})
    if not added then
      ulatency.add_flag(flag)
    end
    ulatency.set_flags_changed(1)
    ulatency.run_iteration() -- scheduler should detect shutdown and quit the daemon
  end
  ulatency.add_timeout(ulatency.fallback_quit, 0) -- instant quit or fallback quit if scheduler is buggy
end

--! @public @memberof ulatency
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

--! @name system flags manipulation
--! @{

--! @public @memberof ulatency
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

--! @brief bla2
--! @public @memberof ulatency
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
--! @} End of "system flags manipulation"

--! Searches `haystack` (list of flags, system flags or process flags) for given flags and returns true
--! if at least one flag was found.
--! @param needles Array of searched flags. Each item may be either the __flag name__ or __table of flag values__<br />
--! For example:@code
--!   {"pressure", "emergency"}
--!   { {name: "pressure", reason: "memory"}, "emergency" }
--! @endcode
--! @param where Defines haystack of flags to be searched through, this may be `table`, `u_proc` instance or `nil`:
--! - __table__: search through given table of flags
--! - __u_proc__: search through flags of that process
--! - __nil__: search through system flags
--! @return boolean TRUE if at least one flag matches
--! @note Examples:@code
--!   ulatency.match_flag({"emergency", {name: "pressure", reason: "memory"}})
--!   ulatency.match_flag({"user.idle", "daemon.idle"}, proc)
--! @endcode
--! @public @memberof ulatency
function ulatency.match_flag(needles, where)
  local lst
  if type(where) == "userdata" then       -- "where" is proc, get its flags
    lst = where:list_flags()
  else
    lst = where or ulatency.list_flags()  -- "where" is already flags list or if nil, get system flag
  end

  for j, flag in pairs(lst) do

    local in_flag, matching = false, false
    for k, needle in pairs(needles) do
      if type(k) == "string" then
        if matching or not in_flag then
          in_flag=true
          matching = flag[k] == needle
        end
      else
        if in_flag and matching then return true end
        in_flag = false
        if type(needle) == "table" then
          if ulatency.match_flag(needle, {flag}) then return true end
        elseif type(k) == "number" then
          if flag.name == needle then return true end
        else
          ulatency.log_warning('ulatency.match_system_flag called with invalid format')
          return nil
        end
      end
    end
    if in_flag and matching then return true end

  end
  return false
end

-- load defaults.conf
if(not ulatency.load_rule("../cgroups.conf")) then
  if(not ulatency.load_rule("../conf/cgroups.conf")) then
    ulatency.log_error("can't load defaults.conf")
  end
end

--! @brief list of usefull mountpoints
--! @private @memberof ulatency
ulatency.mountpoints = {}

--! @brief fill ulatency.mountpoints
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

--! @public @memberof ulatency
function ulatency.tree_loaded(name)
  return __CGROUP_LOADED[name]
end

--! @brief returns true if name is available
--! @private @memberof ulatency
--! @param name name of subsystem to test
function ulatency.has_cgroup_subsystem(name)
  if not __CGROUP_HAS then
    ulatency.get_cgroup_subsystems()
  end
  return (__CGROUP_HAS[name] == true)
end

--!@brief returns a table of available cgroup subsystems
--!@public @memberof ulatency
function ulatency.get_cgroup_subsystems()
  if __CGROUP_AVAIL then
    return __CGROUP_AVAIL
  end
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

--! @name reading / writing to /proc/sys
--! @{

--! @public @memberof ulatency
function ulatency.get_sysctl(name)
  local pname = string.gsub(name, "%.", "/")
  local fp = io.open("/proc/sys/" .. pname)
  if not fp then
    return nil
  end
  local data = fp:read("*a")
  fp:close()
  return data
end

--! @public @memberof ulatency
function ulatency.set_sysctl(name, value)
  local path = "/proc/sys/" .. string.gsub(name, "%.", "/")
  return sysfs_write(path, value)
end
--! @} End of "reading / writing to /proc/sys"

-- CGroups interface

if ulatency.get_uid() > 0 or 
   ulatency.get_config("logging", "disable_cgroup") == "true" then
  ulatency.log_info("disable cgroups error logging. not running as root")
  function cg_log(...)
  end
else
  cg_log = ulatency.log_warning
end

--! @addtogroup lua_CGROUPS
--! @{

--! @brief Returns cgroups of the #u_proc process; two tables are returned: first one contains paths
--! under the root directory where the subsystem hierarchy is mounted, second one contains CGroup instances, if any;
--! both tables are indexed by the cgroup subsystem.
--! @warning Neither hierarchies identifications nor their mount points are returned. This assumes that ulatencyd knows
--! where each subsystem is mounted (e.g. under standard `/sys/fs/cgroup/<subsystem>`) and that every subsystem is
--! mounted as a standalone hierarchy.
--! @note You may want to use this instead of
--! - parsing `u_proc.cgroup` value, which is updated only once per iteration and so does not reflect previous changes
--!   caused by the rules or scheduler mappings
--! - updating and then parsing the `u_proc.cgroup` (e.g. `ulatency.process_update(pid)`), which can cause unexpected
--!   situations (e.g. if the process does no more exist)
--! - parsing `/proc/<pid>/cgroup` content, which may cause unwanted overhead (and the process may not already exist too)
--! @internal
--! @note
--! **How does it work:**
--! Paths of cgroups are internally stored in `u_proc.data.cgroups`; initially parsed from `u_proc.cgroup` and updated
--! by `u_proc:add_cgroup()`, which should be called by every function that moves a process between cgroups.
--! Further to this, the `u_proc.data._cgroup` contains a copy of `u_proc.cgroup`, these are compared to check if the
--! cache values are still valid or the `u_proc.cgroup` must be parsed again.@endinternal
--! @return `<paths>`, `<cgroups`> tables
--! @retval <paths> example:@code
--!   { cpuset = '/', cpu = '/usr_1000/grp_14067', memory = '/usr_1000/default', blkio = '/grp_14067', freezer = '/' }
--! @endcode
--! @retval <cgroups> example:@code
--!   { cpuset = nil, cpu = <CGroup instance>, memory = <CGroup instance>, blkio = <CGroup instance>, freezer = nil }
--! @endcode
--! @public @memberof u_proc

function u_proc:get_cgroups()
  -- validate
  local valid=false
  if self.data.cgroups and self.data._cgroup then
    local a=self.data._cgroup
    local b=self.cgroup
    if #a == #b then
      for i,j in ipairs(a) do
        if b[i] ~= j then break end
      end
      valid=true
    end
  end

  if not valid then
    local cgroups = {}
    for _,line in ipairs(self.cgroup) do
      local subsystems, path  = string.match(line,"^[0-9]+:(.+):(.+)")
      for _,subsys in ipairs(subsystems:split(',')) do
        cgroups[subsys] = path
      end
    end
    self.data._cgroup = self.cgroup
    self.data.cgroups = cgroups
  end

  local cgroup_instances = {}
  for subsys,path in pairs(self.data.cgroups) do
    cgroup_instances[subsys] = CGroup.get_group(subsys .. path)
  end

  return self.data.cgroups, cgroup_instances
end

--! @brief Updates internal list of cgroups which the #u_proc belongs to.
--! This should be called every time a process is moved between cgroups, otherwise the `u_proc:get_cgroups()`
--! won't return correct cgroups until the #u_proc.cgroup will be updated (once per iteration).
--! Internally this function is called everytime CGroup instance is committed, so you should not be bothered.
--! @public @memberof u_proc
function u_proc.add_cgroup(self, cgroup)
  if not self.data.cgroups then
    self:get_cgroups()
  end
  self.data.cgroups[cgroup.tree] = '/'..cgroup.name
end
--! @} End of "addtogroup lua_CGROUPS"

--! @class CGroup
--! @ingroup lua_CORE lua_CGROUPS
CGroup = {}

local _CGroup_Cache = {}

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
    if string.find(line, mnt_pnt.." ") then
      return true
    end
  end
  return false
end

-- try mounting the mountpoints
if not is_mounted(CGROUP_ROOT) then
  -- try mounting a tmpfs there
  mkdirp(CGROUP_ROOT)
  local prog = "/bin/mount -n -t tmpfs none "..CGROUP_ROOT.."/"
  ulatency.log_info("mount cgroups root: "..prog)
  fd = io.popen(prog, "r")
  print(fd:read("*a"))
  if not is_mounted(CGROUP_ROOT) then
    ulatency.log_error("can't mount: "..CGROUP_ROOT)
  end
end

-- disable the autogrouping
if posix.access("/proc/sys/kernel/sched_autogroup_enabled") == 0 then
  ulatency.log_info("disable sched_autogroup in linux kernel")
  ulatency.set_sysctl("kernel.sched_autogroup_enabled", "0")
end

ulatency.log_info("available cgroup subsystems: "..table.concat(ulatency.get_cgroup_subsystems(), ", "))

local __found_one_group = false
for _,subsys in pairs(CGROUP_SUBSYSTEMS) do
  if ulatency.has_cgroup_subsystem(subsys) then
    local path = CGROUP_ROOT..subsys
    if is_mounted(path) then
      ulatency.log_info("mount point "..path.." is already mounted")
      __CGROUP_LOADED[subsys] = true
      __found_one_group = true
    else
      mkdirp(path)
      local prog = "/bin/mount -n -t cgroup -o "..subsys.." none "..path.."/"
      ulatency.log_info("mount cgroups: "..prog)
      fd = io.popen(prog, "r")
      print(fd:read("*a"))
      if not is_mounted(path) then
        ulatency.log_error("can't mount: "..path)
      else
        __CGROUP_LOADED[subsys] = true
        __found_one_group = true
      end
    end
    local fp = io.open(path.."/release_agent", "r")
    local ragent = fp:read("*a")
    fp:close()
    -- we only write a release agent if not already one. update if it looks like
    -- a ulatencyd release agent
    if ragent == "" or ragent == "\n" or string.sub(ragent, -22) == '/ulatencyd_cleanup.sh' then
      sysfs_write(path.."/release_agent", ulatency.release_agent)
    end
    sysfs_write(path.."/notify_on_release", "1")
  else
    ulatency.log_info("no cgroups subsystem "..subsys.." found. disable group")
  end
end

if not __found_one_group then
  ulatency.log_error("could not found one cgroup to mount.")
end
__found_one_group = nil

CGroupMeta = { __index = CGroup, __tostring = CGroup_tostring}

--! @addtogroup lua_CGROUPS
--! @{

--! @brief Creates a new CGroup in _CGroup_Cache; if that CGroup already exists, it is replaced.
--! @warning If the CGroup already exists in _CGroup_Cache, it is replaced, so you will loose its
--! adjusted parameters, adjust functions etc. Prior you create new CGroup, you should always check if it
--! doesn't already exist. You may check that with CGroup.get_group(name).
--! @param name A CGroup path under the directory where `tree` hierarchy is mounted, e.g. `usr100/active`
--! @param init Initial parameters of CGroups, these will not be committed until CGroup:commit() is explicit called.
--! @param tree A tree (cgroup subsystem)
--! @public @memberof CGroup
function CGroup.new(name, init, tree)
  tree = tree or "cpu"
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

--! @public @memberof CGroup
function CGroup.get_groups()
  return _CGroup_Cache
end

--! @brief Returns CGroup or nil, if it does not exist or is not present in ulatency internal _CGroup_Cache.
--! @param name A key of _CGroup_Cache table index, `subsystem`/`cgroup path`, e.g. `cpu/usr1000/active`
--! @return #CGroup | nil | false
--! @retval #CGroup instance, if the _CGroup_Cache table contains the CGroup and that cgroup directory exists.
--! @retval nil If the CGroup directory does not exist or the CGroup is not present in ulatency internal _CGroup_Cache.
--! @public @memberof CGroup
function CGroup.get_group(name)
  local cgr = _CGroup_Cache[name]
  if cgr then
    local stat=posix.stat(cgr:path())
    return (stat and stat.type == 'directory') and cgr or nil
  end
  return nil
end

--! @public @memberof CGroup
function CGroup:path(file)
  if file then
    return CGROUP_ROOT .. self.tree .. "/".. self.name .. "/" .. tostring(file)
  else
    return CGROUP_ROOT .. self.tree .. "/" .. self.name
  end
end

--! @public @memberof CGroup
function CGroup:path_parts()
  return self.name:split("/")
end

--! @public @memberof CGroup
function CGroup:parent()
  parts = self.name:split("/")
  name = table.concat(parts, "/", 1, #parts-1)
  if _CGroup_Cache[name] then
    return _CGroup_Cache[name]
  end
  return CGroup.new(name)
end

--! @public @memberof CGroup
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

--! @public @memberof CGroup
function CGroup:set_value(key, value)
  uncommited = rawget(self, "uncommited")
  uncommited[key] = value
end

--! @public @memberof CGroup
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

--! @public @memberof CGroup
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

--! @public @memberof CGroup
function CGroup:run_adjust(proc)
  adjust = rawget(self, "adjust")
  for i,v in ipairs(adjust) do
    v(self, proc)
  end
end

--function CGroup:adjust()
--  return rawget(self, "adjust")
--end

--! @public @memberof CGroup
function CGroup:add_task_list(pid, tasks)
  local nt = rawget(self, "new_tasks")
  if not nt then
    nt = {}
    rawset(self, "new_tasks", nt)
  end
  for i,v in ipairs(tasks) do
      nt[#nt+1] = v
  end
end

--! @public @memberof CGroup
function CGroup:add_task(pid)
  local nt = rawget(self, "new_tasks")
  if not nt then
    nt = {}
    rawset(self, "new_tasks", nt)
  end
  nt[#nt+1] = pid
end

--! @public @memberof CGroup
function CGroup:is_dirty()
  if #rawget(self, "uncommited") > 0 or
     #rawget(self, "new_tasks") > 0 or 
     posix.access(self:path()) ~= 0 then
     return true
  end
  return false
end

--! @public @memberof CGroup
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

--! @public @memberof CGroup
function CGroup:can_be_removed()
  if self:has_tasks() or #rawget(self, "new_tasks") > 0 then
    return false
  end
  return true
end

--! @public @memberof CGroup
function CGroup:remove()
  ulatency.log_debug(string.format("CGroup:remove('%s')", self:path()))
  if posix.access(self:path()) ~= 0 then
    return true --does not exist
  end
  local rv,error=posix.rmdir(self:path())
  if not rv then
    ulatency.log_debug(error)
  end
  return rv
end

--! @public @memberof CGroup
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
    if sysfs_write(path, v, par == '?') or par == '?' then
      uncommited[k] = nil
    end
  end
  local pids = rawget(self, "new_tasks")
  if #pids > 0 then
    local t_file = self:path("tasks")
    local fp = io.open(t_file, "w")
    if fp then
      fp:setvbuf("no")
      for i, pid in ipairs(pids) do
        local ok, err, err_code = fp:write(tostring(pid)..'\n')
        if not ok then
          sysfs_write_error(t_file, tostring(pid), err, err_code)
        else
          local proc = ulatency.get_pid(pid)
          if proc then
            proc:add_cgroup(self)
          end
        end
      end
      ulatency.log_sched("Move to "..tostring(self).." tasks: "..table.concat(pids, ","))
      rawset(self, "new_tasks", {})
      fp:close()
    end
  end
end

--! @public @memberof CGroup
function CGroup:add_children(proc)
  function add_childs(list)
    for i,v in pairs(list) do
      self:run_adjust(v)
      self:add_task_list(v.pid, v:get_current_task_pids())
    end
    for i,v in pairs(list) do
      add_childs(v:get_children())
    end
  end
  add_childs(proc:get_children())
end

--! @brief Isolates the process: the passed #u_proc instance is marked to be skipped by scheduler and
--! moved to isolation cgroups iso_<`suffix`> under each cgroup subsystem.
--! @param proc #u_proc to isolate
--! @param suffix (optional) The suffix of the new CGroup name: `iso_<suffix>` or `iso_<pid>`, if the suffix is nil.
--! @param mappings A table with the CGroup @link __ISOLATE_MAPPING mappings@endlink per each cgroups subsystem.
--! \endcode
--! @param include_children (optional) If TRUE, the `proc` children are recursively put to the isolation.
--! @param block_scheduler (optional) `u_proc.set_block_scheduler()` argument, defaults to 1
--! @param fnc (optional) If passed, this function will be called with the every #u_proc putting into isolation.
--! @public @memberof CGroup
function CGroup.create_isolation_group(proc, suffix, mappings, include_children, block_scheduler, fnc)

  local tasks = proc:get_current_task_pids()
  local cgr_name = "iso_"..suffix or tostring(pid)
  for x,subsys in ipairs(ulatency.get_cgroup_subsystems()) do
    if ulatency.tree_loaded(subsys) then
      -- create isolation cgroup
      local mapping = mappings[subsys] or {}
      local ng =  CGroup.get_group(subsys .."/".. cgr_name)
      if not ng then
        ng = CGroup.new(cgr_name, mapping.params or {}, subsys)
        ng:commit()
        if mapping.adjust then
          ng.adjust[#ng.adjust+1] = mapping.adjust
        end
        if mapping.adjust_new then
          mapping.adjust_new(ng, proc)
        end
        ng:commit()
        ulatency.log_info(string.format('isolation group %s created.', ng:path()))
      end
      ng:run_adjust(proc)
      ng:add_task_list(proc.pid, tasks)
      if include_children then
        ng:add_children(proc)
      end
      ng:commit()
    end
  end

  local block = block_scheduler or 1
  local proc_fnc = function(proc) if fnc then fnc(proc) end; proc:set_block_scheduler(block) end
  if include_children then
    proc:apply(proc_fnc)
  else
    proc_fnc(proc)
  end
end

--! @public @memberof CGroup
function CGroup:starve(what)
  if what == "memory" then
    nv = self:get_value("memory.usage_in_bytes", true)
    if nv then
      self:set_value("memory.limit_in_bytes", nv)
    end
  end
end

--! @} End of "addtogroup lua_CGROUPS"

--! @addtogroup lua_HELPERS
--! @{

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


function num_or_percent(conf, value, default)
  local rv = false
  if not conf and default then
    conf = default
  end
  if not conf then
    conf = "100%"
  end
  for w in string.gmatch(conf, "(%d+)%%") do
     return ((value)/100)*tonumber(w)
  end
  if not conf then
    return value
  end
  return conf
end
--! @} End of "defgroup helper Helper classes"

--! @brief Recursively applies the function to #u_proc and its children.
--! @param fnc A function to apply. It will be called with #u_proc passed recursively on the #u_proc and all its
--! children.
--! @public @memberof u_proc
function u_proc:apply(fnc)
  local function adjust(list)
    for _,p in ipairs(list) do
      adjust(p:get_children())
      fnc(p)
    end
  end
  adjust(self:get_children())
  fnc(self)
end
