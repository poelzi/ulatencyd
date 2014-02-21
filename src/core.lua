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

--! @brief remove trailing whitespace from string.
--! http://en.wikipedia.org/wiki/Trim_(8programming)
function string:rtrim()
  local n = #self
  while n > 0 and self:find("^%s", n) do n = n - 1 end
  return self:sub(1, n)
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
--! @retval 0 if the directory was successfully created.
--! @retval nil, errstr, errno if creation of some directory along the `path` failed.
function mkdirp(path)
  if not posix.access(path, "f") then
    local parts = path:split("/")
    for i,v in ipairs(parts) do
      name = "/" .. table.concat(parts, "/", 1, i)

      if not posix.access(name, "f") then -- this fail if `name`
                  -- (e.g /sys/fs/cgroup/cpu) is a symlink not created by root
        local ok, errstr, errno = posix.mkdir(name)
        if not ok then
          cg_log(string.format(
                "mkdirp(%s): Can't create directory: %s",
                path, errstr))
          return nil, errstr, errno
        end
      end

    end
  end
  return 0
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

--!@brief Returns a table of available cgroup subsystems.
--!@public @memberof ulatency

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

-- CGroups interface

if ulatency.get_uid() > 0 or 
   ulatency.get_config("logging", "disable_cgroup") == "true" then
  ulatency.log_info("disable cgroups error logging. not running as root")
  function cg_log(...)
  end
else
  cg_log = ulatency.log_warning
end

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
CGROUP_PRIVATE_ROOT = CGROUP_ROOT .. "ulatencyd/"

-- test if path is mounted
local function is_mounted(path)
  if string.sub(path, #path) == "/" then
    path = string.sub(path, 1, #path-1)
  end
  for line in io.lines("/proc/mounts") do
                  --fixme handle octal codes (like \040 for space)
    local mnt = line:match("^[^%s]+%s+([^%s]+)%s+")
    if mnt == path then
      return true
    end
  end
  return false
end

-- return path (or nil) where is mounted cgroup hierarchy of given subsystem
local function get_subsys_mount_point(subsys)
  for line in io.lines("/proc/mounts") do
                        --fixme handle octal codes (like \040 for space)
    local mnt, opts = line:match("^[^%s]+%s+([^%s]+)%s+cgroup%s+([^%s]+)")
    if mnt and string.find(","..opts..",", ","..subsys..",") then
      return mnt
    end
  end
  return nil
end

-- return table of subsystems mounted in given path
local function get_mount_point_subsystems(path)
  if string.sub(path, #path) == "/" then
    path = string.sub(path, 1, #path-1)
  end
  for line in io.lines("/proc/mounts") do
    local mnt = line:match("^[^%s]+%s+([^%s]+)%s+")
    if mnt == path then

                      ---fixme handle octal codes (like \040 for space)
      local opts = line:match("^[^%s]+%s+[^%s]+%s+cgroup%s+([^%s]+)")
      rv = {}
      if opts then
        local mounted_subsystems = string.split(opts, ",")
        for _, known_subsys in pairs(CGROUP_SUBSYSTEMS) do
          if ulatency.has_cgroup_subsystem(known_subsys) then
            for _, mnt_subsys in pairs(mounted_subsystems) do
              if mnt_subsys == known_subsys then
                rv[#rv+1] = mnt_subsys
              end
            end
          end
        end
      end
      return rv

    end
  end
  return nil
end

-- try to mount CGROUP_ROOT

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

-- create CGROUP_PRIVATE_ROOT

if posix.access(CGROUP_PRIVATE_ROOT) ~= 0 then
  if not mkdirp(CGROUP_PRIVATE_ROOT) then
    ulatency.log_error("can't create directory for ulatencyd private cgroup hierarchies: "..CGROUP_PRIVATE_ROOT)
  end
end

-- disable the autogrouping

if posix.access("/proc/sys/kernel/sched_autogroup_enabled") == 0 then
  ulatency.log_info("disable sched_autogroup in linux kernel")
  ulatency.save_sysctl("kernel.sched_autogroup_enabled", "0")
end

ulatency.log_info("available cgroup subsystems: "..table.concat(ulatency.get_cgroup_subsystems(), ", "))


local __found_one_group = false

local function setup_cgroups_hierarchy(subsys)
  local wanted_mountpoint = CGROUP_ROOT..subsys
  local real_mountpoint = get_subsys_mount_point(subsys) -- if already mounted

  -- track if we created mountpoint, symlink or mounted the subsystem
  -- hierarchy to rembeber we should revert these actions, if subsequent
  -- mounting of private hierarchy will fail.
  local mounted = false
  local created_mountpoint = false
  local created_symlink = false

  -- log shortcuts
  local function log_info(msg)
    ulatency.log_info("setup "..subsys..": "..msg)
  end
  local function log_warning(msg)
    ulatency.log_warning("setup "..subsys..": "..msg)
  end

  log_info(string.format(
        "Setup hierarchy of control groups for %s subsystem.", subsys))

  if (real_mountpoint) then
    local mounted_subsystems = get_mount_point_subsystems(real_mountpoint)
    if mounted_subsystems then
      for _, mnt_subsys in ipairs(mounted_subsystems) do
        if __CGROUP_LOADED[mnt_subsys] then
          log_warning(string.format(
                "This subsystem is surprisingly already mounted in hierarchy"..
                " shared with another subsystem (%s).",
                mnt_subsys))
          log_warning(
                "Ulatencyd supports only one subsystem per cgroups"..
                " hierarchy. If you REALLY need this type of setup, for a"..
                " price of unoptimal scheduling, contact ulatencyd authors.")
          return false
        end
      end
    end
  end

  -- if cgroup is already mounted as we need, skip remaining checks
  if (real_mountpoint == wanted_mountpoint) then
    log_info("Hierarchy already mounted in expected "..wanted_mountpoint..".")

  -- if hierarchy is already mounted but in unexpected mount point,
  -- check if we can use existent symlink to it or create new one
  elseif (real_mountpoint and real_mountpoint ~= wanted_mountpoint) then
    log_info(string.format(
          "Hierarchy surprisingly already mounted in %s, trying symbolic link.",
          real_mountpoint))
    -- check if symlink exists
    local prog = string.format("/bin/readlink -eqn '%s'", wanted_mountpoint)
    local fd = io.popen(prog, "r")
    local target = fd:read("*a")
    fd:close()
    -- if symlink already exists, check if it links to hierarchy mount point
    if #target > 0 and target == real_mountpoint then
      log_info(string.format(
            "Using existing symbolic link %s.", wanted_mountpoint))
    else
    -- create symbolic link (this will fail if file or directory of same name
    -- already exists, so we need not to check these conditions
      local target = real_mountpoint:find(CGROUP_ROOT, 1, true) == 1
                and real_mountpoint:sub(#CGROUP_ROOT+1) .. "/"
                or real_mountpoint .. "/"
      local ok, errstr = posix.link(
            target,
            wanted_mountpoint, true)
      if (not ok) then
        log_warning(string.format(
              "Cannot create symbolic link %s to %s : %s",
              wanted_mountpoint, target, errstr))
        return false
      else
        created_symlink = true
        log_info(string.format(
              "Using created symbolic link %s.",
              wanted_mountpoint, target))
      end
    end

  -- if hierarchy is not mounted then mount it...
  else
  -- but first check that the mount point is not used.
  -- there may be even another subsystem!
    if is_mounted(wanted_mountpoint) then
      log_warning(string.format(
            "Surprisingly there is something already mounted in %s! Giving up.",
            wanted_mountpoint))
      return false
    end
    -- create mount point
    if not posix.access(wanted_mountpoint, "f") then
      local ok, errstr = mkdirp(wanted_mountpoint)
      if not ok then
        log_warning(string.format(
              "Directory %s cannot be created: %s", wanted_mountpoint, errstr))
        return false
      end
      created_mountpoint = true
    end
    -- mount hierarchy
    local options = subsys
    local device = "none"
    local prog = string.format("/bin/mount -n -t cgroup -o %s %s %s/ 2>&1",
                               options, device, wanted_mountpoint)
    log_info(string.format(
          "Mounting hierachy: \"%s\"", prog))
    local fd = io.popen(prog, "r")
    local output = fd:read("*a"):rtrim()
    fd:close()
    if #output > 0 then
      log_warning(output)
    end
    if is_mounted(wanted_mountpoint) then
      mounted = true
    else
      log_warning("Cannot mount cgroups hierarchy.")
      if (created_mountpoint) then -- cleanup
        log_info("Reverting changes we have done:")
        log_info("rm "..wanted_mountpoint)
        os.remove(wanted_mountpoint)
      end
      return false
    end
  end

  -- check if we have permissions to access the hierarchy,
  -- we shouldn't have if it is symlink created by a regular user
  local access, err_msg = posix.access(wanted_mountpoint, "rwx")
  if not access then
    log_warning("Cannot access hierarchy: "..err_msg)
    return false
  end

  --
  -- Mount ulatencyd private hierachy.
  --

  local priv_subsys = "name=ulatencyd."..subsys
  local wanted_priv_mountpoint = CGROUP_PRIVATE_ROOT..subsys
  local real_priv_mountpoint = get_subsys_mount_point(priv_subsys)
  local failed = false
  local priv_mounted = false

  -- check if the private hierarchy is not already mounted
  if (real_priv_mountpoint == wanted_priv_mountpoint) then
    priv_mounted = true
    log_info(string.format(
          "Private hierarchy already mounted in expected %s.",
          wanted_mountpoint))

  elseif (real_priv_mountpoint and
          real_priv_mountpoint ~= wanted_priv_mountpoint)
  then
    failed = true
    log_warning(string.format(
          "Private hierarchy surprisingly already mounted in %s! Giving up.",
          real_priv_mountpoint))
  end

  -- check that the mount point is not used.
  -- there may be even another subsystem!
  if not failed and not priv_mounted and is_mounted(wanted_priv_mountpoint) then
    log_warning(string.format(
          "Surprisingly there is already something mounted in %s! Giving up.",
          wanted_priv_mountpoint))
    failed = true
  end

  if not failed and not priv_mounted then
    -- create mount point
    if not posix.access(wanted_priv_mountpoint, "f") then
      local ok, errstr = mkdirp(wanted_priv_mountpoint)
      if not ok then
        log_warning(string.format(
              "Directory %s cannot be created: %s",
              wanted_priv_mountpoint, errstr))
        failed = true
      end
    end

    if (not failed) then
      local options = "none,name=ulatencyd."..subsys
      -- we mount private hierarchies with the fake device (first column in /proc/mounts)
      -- corresponding to the directory where hierarchy with the real cgroup subsystem controller
      -- is mounted. This way the userspace scripts (e.g. ulatency) are able to map
      -- our private hierarchy to the real one.
      local device = wanted_mountpoint
      local prog = string.format("/bin/mount -n -t cgroup -o %s %s %s/ 2>&1",
                                 options, device, wanted_priv_mountpoint)
      log_info(string.format(
          "Mounting private hierachy: \"%s\"", prog))
      local fd = io.popen(prog, "r")
      local output = fd:read("*a"):rtrim()
      fd:close()
      if #output > 0 then
        log_warning(output)
      end
      if not is_mounted(wanted_priv_mountpoint) then
        log_warning("Cannot mount private hierarchy.")
        failed = true
      end
    end
  end

  if (failed) then
    log_info("Reverting changes we have done:")
    -- cleanup
    log_info("rmdir "..wanted_priv_mountpoint)
    os.remove(wanted_priv_mountpoint)
    if (mounted) then
      local prog = "/bin/umount "..wanted_mountpoint
      log_info(prog)
      io.popen(prog, "r")
    end
    if (created_mountpoint or created_symlink) then
      log_info("rm "..wanted_mountpoint)
      os.remove(wanted_mountpoint)
    end
    return false
  end

  __CGROUP_LOADED[subsys] = true
  __found_one_group = true
  return true
end


for _,subsys in pairs(CGROUP_SUBSYSTEMS) do
  if ulatency.has_cgroup_subsystem(subsys) then
    if setup_cgroups_hierarchy(subsys) then
      local path = CGROUP_ROOT..subsys;
      local fp = io.open(path.."/release_agent", "r")
      local ragent = fp:read("*a"):rtrim()
      fp:close()
      -- we only write a release agent if not already one. update if it looks like
      -- a ulatencyd release agent
      if ragent == "" or ragent == "\n" or string.sub(ragent, -21) == '/ulatencyd_cleanup.sh' then
        sysfs_write(path.."/release_agent", ulatency.release_agent)
        sysfs_write(path.."/notify_on_release", "1")
      else
        ulatency.log_info("setup "..subsys..": Foreign released agent "..
                    "already registered: "..ragent)
      end
      ulatency.log_info("setup "..subsys..": Done.")
    else
      ulatency.log_warning("setup "..subsys..": Subsystem disabled.")
    end
  elseif ulatency.has_cgroup_subsystem(subsys) == nil then
    ulatency.log_info(
                "setup "..subsys..": Subsystem not found, disabling.")
  else
    ulatency.log_warning(
                "setup "..subsys..": Subsystem supported by kernel, but"..
                " currently disabled. It may be enabled with a boot"..
                " time parameter of Linux kernel.")
  end
end

if not __found_one_group then
  ulatency.log_error("Could not found any cgroup to mount.")
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

--! @brief Returns true, if the cgroup was created outside ulatencyd..
--! @param subsys A cgroup subsystem.
--! @param hierarchy_path Path under cgroup hierarchy
--! @return boolean
--! @public @memberof CGroup
function CGroup.is_foreign(subsys, hierarchy_path)
  local cgr_name = subsys .. hierarchy_path
  if hierarchy_path == "/" or CGroup.get_group(cgr_name) then
    return false
  end
  local priv_cgr_path = CGROUP_PRIVATE_ROOT .. subsys .. "/".. hierarchy_path
  local stat=posix.stat(priv_cgr_path)
  return not (stat and stat.type == 'directory')
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
function CGroup:private_path(file)
  if file then
    return CGROUP_PRIVATE_ROOT .. self.tree .. "/".. self.name .. "/" .. tostring(file)
  else
    return CGROUP_PRIVATE_ROOT .. self.tree .. "/" .. self.name
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
    return fp:read("*a"):rtrim()
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
  if posix.access(t_file, "r") ~= 0 then
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
  if posix.access(t_file, "r") ~= 0 then
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

local function _rmdir(path)
  if posix.access(path) ~= 0 then
    --does not exist, still must be removed from ulatencyd hierarchy,
    --so return true here
    return true
  end
  local rv,error=posix.rmdir(path)
  if not rv then
    ulatency.log_debug(error)
  end
  return rv
end

--! @public @memberof CGroup

function CGroup:remove()
  ulatency.log_debug(string.format("CGroup:remove('%s')", self:path()))
  local rv = _rmdir(self:path())
  if rv then
    _rmdir(self:private_path())
  end
  return rv
end

--! @public @memberof CGroup
function CGroup:commit()
  mkdirp(self:path())
  mkdirp(self:private_path())
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
          if not ulatency.is_pid_alive(pid) then --suppres warning if the task is already dead
            sysfs_write_error(t_file, tostring(pid), err, err_code)
          end
        else
          local proc = ulatency.get_pid(pid)
          if proc then
            proc:set_cgroup(self.tree, "/".. self.name)
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
      local tasks = v:get_current_task_pids()
      if tasks then --nil if the process is already dead
        self:add_task_list(v.pid, tasks)
      end
    end
    for i,v in pairs(list) do
      add_childs(v:get_children())
    end
  end
  add_childs(proc:get_children())
end

--! @brief Isolates the process: the passed #U_PROC instance is marked to be skipped by scheduler and
--! moved to isolation cgroups iso_<`suffix`> under each cgroup subsystem.
--! @param proc #U_PROC to isolate
--! @param suffix (optional) The suffix of the new CGroup name: `iso_<suffix>` or `iso_<pid>`, if the suffix is nil.
--! @param mappings A table with the CGroup @link __ISOLATE_MAPPING mappings@endlink per each cgroups subsystem.
--! \endcode
--! @param include_children (optional) If TRUE, the `proc` children are recursively put to the isolation.
--! @param block_scheduler (optional) `U_PROC::set_block_scheduler()` argument, defaults to 1
--! @param fnc (optional) If passed, this function will be called with the every #U_PROC putting into isolation.
--! @public @memberof CGroup
function CGroup.create_isolation_group(proc, suffix, mappings, include_children, block_scheduler, fnc)

  local tasks = proc:get_current_task_pids()
  if not tasks then return end --process is already dead
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

--! @brief Recursively applies the function to #U_PROC and its children.
--! @param fnc A function to apply. It will be called with #U_PROC passed recursively on the #U_PROC and all its
--! children.
--! @public @memberof U_PROC
function U_PROC:apply(fnc)
  local function adjust(list)
    for _,p in ipairs(list) do
      adjust(p:get_children())
      fnc(p)
    end
  end
  adjust(self:get_children())
  fnc(self)
end
