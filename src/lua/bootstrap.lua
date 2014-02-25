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
--! @brief ulatencyd lua bootstrap
---------------------------------

posix = require("posix")

-- load functions from other modules.
-- modules should only define functions and do not run any code which requires
-- other modules

for _, module in ipairs
  {
    "table", "string", "misc",
    "ulatency", "cgroup", "u_proc"
  }
do
  if not ulatency.load_core_file(module..".lua") then
    ulatency.log(ulatency.LOG_LEVEL_ERROR, string.format(
          "bootstrap: Can't required load %s.lua", module ))
  end
end


-- load cgroups.conf

if(not ulatency.load_rule("../cgroups.conf")) then
  if(not ulatency.load_rule("../conf/cgroups.conf")) then
    ulatency.log_error("can't load cgroups.conf")
  end
end


-- check if sysfs and debugs are mounted

do
  local fp = io.open("/proc/mounts")
  local good = { sysfs=true, debugfs=true }

  if not fp then
    ulatency.log_error("/proc/mounts could not be opened.")
  end
  for line in fp:lines() do
    local chunks = string.split(line, " ")
    if good[chunks[3]] then
      ulatency.mountpoints[chunks[3]] = chunks[2]
    end
  end
  fp:close()
end

if not ulatency.mountpoints["sysfs"] then
  ulatency.log_error("sysfs is not mounted.")
end


-- disable logging of cgroups creation errors 

if ulatency.get_uid() > 0 or 
   ulatency.get_config("logging", "disable_cgroup") == "true" then
  ulatency.log_info("disable cgroups error logging. not running as root")
  function cg_log(...)
  end
else
  cg_log = ulatency.log_warning
end


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


-- prepare CGROUP_ROOT and CGROUP_ROOT_PRIVATE mount points

if string.sub(CGROUP_ROOT, -1) ~= "/" then
  CGROUP_ROOT = CGROUP_ROOT .. "/"
end
CGROUP_PRIVATE_ROOT = CGROUP_ROOT .. "ulatencyd/"

do
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
  if posix.access(CGROUP_PRIVATE_ROOT) ~= 0 then
    if not mkdirp(CGROUP_PRIVATE_ROOT) then
      ulatency.log_error("can't create directory for ulatencyd private cgroup hierarchies: "..CGROUP_PRIVATE_ROOT)
    end
  end
end


-- mount cgroup hierarchies

ulatency.log_info("available cgroup subsystems: "..table.concat(ulatency.get_cgroup_subsystems(), ", "))

local __found_one_group = false

local function mount_cgroup(subsys, private)
  local rv = false
  local subsys_path = CGROUP_ROOT..subsys
  local private_path = CGROUP_PRIVATE_ROOT..subsys
  local mount_path = private and private_path or subsys_path
  if is_mounted(mount_path) then
    ulatency.log_info("mount point "..mount_path.." is already mounted")
    if not private then
      ulatency.set_tree_loaded(subsys)
      __found_one_group = true
    end
    rv = true
  else
    mkdirp(mount_path)
    local options = private and  "none,name=ulatencyd."..subsys or subsys
    -- we mount private hierarchies with the fake device (first column in /proc/mounts)
    -- corresponding to the directory where hierarchy with the real cgroup subsystem controller
    -- is mounted. This way the userspace scripts (e.g. ulatency) are able to map
    -- our private hierarchy to the real one.
    local device = private and subsys_path or "none"
    local prog = "/bin/mount -n -t cgroup -o "..options.." "..device.." "..mount_path.."/"
    ulatency.log_info("mount cgroups: "..prog)
    fd = io.popen(prog, "r")
    print(fd:read("*a"))
    if not is_mounted(mount_path) then
      if private then
        ulatency.log_error("can't mount private cgroup: "..mount_path)
      else
        ulatency.log_warning("can't mount: "..mount_path..", disabling subsystem.")
      end
    else
      ulatency.set_tree_loaded(subsys)
      __found_one_group = true
      rv = true
    end
  end
  return rv
end

for _,subsys in pairs(CGROUP_SUBSYSTEMS) do
  if ulatency.has_cgroup_subsystem(subsys) then
    if mount_cgroup(subsys, false) then
      mount_cgroup(subsys, true)
      local path = CGROUP_ROOT..subsys;
      local fp = io.open(path.."/release_agent", "r")
      local ragent = fp:read("*a")
      fp:close()
      -- we only write a release agent if not already one. update if it looks like
      -- a ulatencyd release agent
      if ragent == "" or ragent == "\n" or string.sub(ragent, -22) == '/ulatencyd_cleanup.sh' then
        sysfs_write(path.."/release_agent", ulatency.release_agent)
      end
      sysfs_write(path.."/notify_on_release", "1")
    end
  else
    ulatency.log_info("no cgroups subsystem "..subsys.." found, disabling subsystem.")
  end
end

if not __found_one_group then
  ulatency.log_error("could not found one cgroup to mount.")
end


-- disable the autogrouping

if posix.access("/proc/sys/kernel/sched_autogroup_enabled") == 0 then
  ulatency.log_info("disable sched_autogroup in linux kernel")
  ulatency.save_sysctl("kernel.sched_autogroup_enabled", "0")
end

