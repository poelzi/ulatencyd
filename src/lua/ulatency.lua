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

-------------------------------------------------------------------------------
--! @file
--! @ingroup lua_CORE
--! @brief ulatency table
-------------------------------------------------------------------------------


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
function ulatency.log_message(msg)
  ulatency.log(ulatency.LOG_LEVEL_MESSAGE, msg)
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
--! @brief Check `/proc` subsystem and return TRUE if process/task with `pid` exists.
function ulatency.is_pid_alive(pid)
  return posix.access('/proc/'..pid) == 0
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
--! @param where Defines haystack of flags to be searched through, this may be `table`, `U_PROC` instance or `nil`:
--! - __table__: search through given table of flags
--! - __U_PROC__: search through flags of that process
--! - __nil__: search through system flags
--! @param (optional) recursive If true, inherited flags are included. Default is to not include them.
--! @return boolean TRUE if at least one flag matches
--! @note Examples:@code
--!   ulatency.match_flag({"emergency", {name: "pressure", reason: "memory"}})
--!   ulatency.match_flag({"user.idle", "daemon.idle"}, proc)
--! @endcode
--! @public @memberof ulatency
function ulatency.match_flag(needles, where, recursive)
  local lst
  if type(where) == "userdata" then       -- "where" is proc, get its flags
    lst = where:list_flags(recursive)
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
          if ulatency.match_flag(needle, {flag}, false) then return true end
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


local __CGROUP_HAS = false
local __CGROUP_AVAIL = false
local __CGROUP_LOADED = {}

--! Returns a table of all cgroup subsystems the Linux kernel supports,
--! including those disabled or not used by ulatencyd.
--! @public @memberof ulatency

function ulatency.get_cgroup_subsystems()
  if __CGROUP_AVAIL then
    return __CGROUP_AVAIL
  end
  __CGROUP_AVAIL = {}
  __CGROUP_HAS = {}
  for line in io.lines("/proc/cgroups") do
    if string.sub(line, 1, 1) ~= "#" then
      local subsys, enabled = line:match("^([%w_]+).*(%d)$")
      if subsys ~= nil then
        __CGROUP_AVAIL[#__CGROUP_AVAIL+1] = subsys
        __CGROUP_HAS[subsys] = (enabled == "1" and true or false)
      end
    end
  end
  return __CGROUP_AVAIL
end

--! @brief Tests whether given cgroup subsystem is available.
--! @private @memberof ulatency
--! @param name Name of subsystem to test.
--! @return false | true | nil
--! @retval nil   If the subsystem is not available in the Linux kernel.
--! @retval false If the cgroup is available but disabled in kernel.
--! @retval true  If the cgroup is available and enabled in kernel.
--! @public @memberof ulatency

function ulatency.has_cgroup_subsystem(name)
  if not __CGROUP_HAS then
    ulatency.get_cgroup_subsystems()
  end
  return __CGROUP_HAS[name]
end

--! @brief Returns true if given cgroups subsystem is loaded by ulatencyd.
--! @public @memberof ulatency
function ulatency.tree_loaded(name)
  return __CGROUP_LOADED[name]
end

--! @brief call this after a cgroups subsystem was loaded by ulatencyd
function ulatency.set_tree_loaded(name)
  __CGROUP_LOADED[name] = true
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

do
  local _saved_sysctl = {}

  --! @brief save old sysctl value and set the new one
  --! @public @memberof ulatency
  function ulatency.save_sysctl(name, new_value)
    local path = "/proc/sys/" .. string.gsub(name, "%.", "/")
    if not _saved_sysctl[name] then
      _saved_sysctl[name] = ulatency.get_sysctl(name)
    end
    return sysfs_write(path, new_value)
  end

  --! @brief restore saved sysctl value
  --! @public @memberof ulatency
  function ulatency.restore_sysctl(name)
    local path = "/proc/sys/" .. string.gsub(name, "%.", "/")
    if not _saved_sysctl[name] then return end
    return sysfs_write(path, _saved_sysctl[name])
  end
end

--! @} End of "reading / writing to /proc/sys"

--! @brief list of useful mount points
--! @public @memberof ulatency
ulatency.mountpoints = {}
