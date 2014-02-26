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



-------------------------------------------------------------------------------
--  Begin setup of cgroups subsystems
-------------------------------------------------------------------------------

ulatency.log_message("Available cgroup subsystems: "..
                   table.concat(ulatency.get_cgroup_subsystems(), ", "))

if string.sub(CGROUP_ROOT, -1) ~= "/" then
  CGROUP_ROOT = CGROUP_ROOT .. "/"
end
CGROUP_PRIVATE_ROOT = CGROUP_ROOT .. "ulatencyd/"


-- return false or true if path is mounted
local function is_mounted(path)
  if string.sub(path, #path) == "/" then
    path = string.sub(path, 1, #path-1)
  end
  for line in io.lines("/proc/mounts") do
                  -- FIXME handle octal codes (like \040 for space)
    local mnt = line:match("^[^%s]+%s+([^%s]+)%s+")
    if mnt == path then
      return true
    end
  end
  return false
end


-- return nil or path where is mounted cgroup hierarchy of given subsystem
local function get_subsys_mount_point(subsys)
  for line in io.lines("/proc/mounts") do
                        -- FIXME handle octal codes (like \040 for space)
    local mnt, opts = line:match("^[^%s]+%s+([^%s]+)%s+cgroup%s+([^%s]+)")
    if mnt and string.find(","..opts..",", ","..subsys..",") then
      return mnt
    end
  end
  return nil
end


-- return nil or table of subsystems mounted in given path
local function get_mount_point_subsystems(mount_point)
  local all_subsystems = ulatency.get_cgroup_subsystems()
  if string.sub(mount_point, #mount_point) == "/" then
    mount_point = string.sub(mount_point, 1, #mount_point-1)
  end
  for line in io.lines("/proc/mounts") do
    local mnt = line:match("^[^%s]+%s+([^%s]+)%s+")
    if mnt == mount_point then
                      --- FIXME handle octal codes (like \040 for space)
      local opts = line:match("^[^%s]+%s+[^%s]+%s+cgroup%s+([^%s]+)")
      rv = {}
      if opts then
        local mounted_subsystems = string.split(opts, ",")
        for _, known_subsys in pairs(all_subsystems) do
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


local function log_info(subsys, ...)
  ulatency.log_info("Setup ".. subsys ..": "..string.format(...))
end


local function log_warning(subsys, ...)
  ulatency.log_warning("Setup ".. subsys ..": "..string.format(...))
end


local function mount_subsystem(subsys, private)
  local new_mount_point, old_mount_point, mnt_options, mnt_device, log_subsys
  if not private then
    log_subsys = subsys
    mnt_options = subsys
    mnt_device = "none"
    new_mount_point = CGROUP_ROOT..subsys
    old_mount_point = get_subsys_mount_point(subsys) -- already mounted
  else
    log_subsys = subsys.." private"
    mnt_options = "none,name=ulatencyd."..subsys
    -- mount private hierarchies with the fake device (first column in
    -- /proc/mounts) corresponding to the directory where is hierarchy with
    -- the real cgroup subsystem controller mounted. This way user space
    -- scripts (e.g. ulatency) are able to map our private hierarchy
    -- to the real one.
    mnt_device = CGROUP_ROOT..subsys
    new_mount_point = CGROUP_PRIVATE_ROOT..subsys
    subsys = "name=ulatencyd."..subsys
    old_mount_point = get_subsys_mount_point(subsys)  -- already mounted
  end

  -- check if new_mount_point is symlink
  local prog = string.format(
        "/bin/readlink -mqn '%s'", new_mount_point)
  local fd = io.popen(prog.." 2>/dev/null", "r")
  local new_mount_point_link = fd:read("*a")
  fd:close()
  if (new_mount_point_link == new_mount_point) then
    new_mount_point_link = nil
  end

  if new_mount_point_link and new_mount_point_link ~= old_mount_point then
    log_warning(log_subsys,
          "%s is a symbolic link pointing to %s. Ulatency refuses to"..
          " use it. Please remove it.", new_mount_point, new_mount_point_link)
    return false
  end

  -- if cgroup is already mounted as we need, skip remaining checks
  if (old_mount_point == new_mount_point) then
    log_info(log_subsys,
          "Hierarchy already mounted in expected %s.", new_mount_point)

  -- if hierarchy is already mounted but in unexpected mount point then fail
  elseif (old_mount_point and old_mount_point ~= new_mount_point) then
    log_warning(log_subsys,
          "Hierarchy already mounted in unexpected %s,"..
          " expected mount point: %s", old_mount_point, new_mount_point)
    -- if symlink already exists, check if it links to hierarchy mount point
    -- but just report it, don't use it
    if new_mount_point_link == old_mount_point then
      log_warning(log_subsys,
            "Symbolic link %s pointing to %s exists but ulatencyd refuses"..
            " to use it.", new_mount_point, old_mount_point)
    end
    return false

  -- if hierarchy is not mounted then mount it...
  else
    -- but first check that the mount point is not used
    if is_mounted(new_mount_point) then
      log_warning(log_subsys,
            "There is something already mounted in %s! Giving up.",
            new_mount_point)
      return false
    -- is not a symbolic link
    elseif new_mount_point_link then
      log_warning(log_subsys,
            "Refusing mount to symbolic link %s.", new_mount_point)
      return false
    end
    -- is a directory
    if posix.access(new_mount_point, "f") then
      local mount_point_type = posix.stat(new_mount_point, "type")
      if mount_point_type ~= 'directory' then
        log_warning(log_subsys,
              "Mount point %s/ is not a directory but %s file.",
              new_mount_point, mount_point_type )
        return false
      end
    -- or can be created
    else
      local ok, errstr = mkdirp(new_mount_point)
      if not ok then
        log_warning(log_subsys,
              "Directory %s cannot be created: %s", new_mount_point, errstr)
        return false
      end
    end

    -- mount hierarchy
    local prog = string.format("/bin/mount -n -t cgroup -o %s %s %s/",
                               mnt_options, mnt_device, new_mount_point)
    log_info(log_subsys, "Mount hierarchy: \"%s\"", prog)
    local fd = io.popen(prog.." 2>&1", "r")
    local output = fd:read("*a"):rtrim()
    fd:close()
    if #output > 0 then
      log_warning(log_subsys, output)
    end
    if not is_mounted(new_mount_point) then
      log_warning(log_subsys, "Cannot mount cgroups hierarchy.")
      return false
    end
  end

  -- finally check we have enough permissions to access it
  -- (maybe useless check)
  if not posix.access(new_mount_point, "rwx") then
    log_warning(log_subsys,
          "Not enough permissions (rwx) to access %s/.", new_mount_point )
  end

  return true
end -- function mount_subsystem(subsys)


do
  -- try to mount tmpfs in CGROUP_ROOT
  if not is_mounted(CGROUP_ROOT) then
    local ok, errstr = mkdirp(CGROUP_ROOT)
    if not ok then
      ulatency.log_error(string.format(
            "Can't create directory for cgroups root %s: %s",
            CGROUP_ROOT, errstr ))
      return false
    end
    local prog = "/bin/mount -n -t tmpfs none "..CGROUP_ROOT.."/"
    ulatency.log_info("Mount cgroups root: "..prog)
    local fd = io.popen(prog, "r")
    local output = fd:read("*a"):rtrim()
    fd:close()
    if #output > 0 then
      ulatency.log_warning(output)
    end
    if not is_mounted(CGROUP_ROOT) then
      ulatency.log_error("Cannot mount: "..CGROUP_ROOT)
    end
  end

  -- create CGROUP_PRIVATE_ROOT
  if posix.access(CGROUP_PRIVATE_ROOT) ~= 0 then
    local ok, errstr = mkdirp(CGROUP_PRIVATE_ROOT)
    if not ok then
      ulatency.log_error(string.format(
            "Can't create directory for ulatencyd private cgroups"..
            " hierarchies %s: %s", CGROUP_PRIVATE_ROOT, errstr ))
    end
  end

  -- check for crippled subsystems
  local crippled_subsystems = false
  for _,subsys in ipairs(CGROUP_SUBSYSTEMS) do -- test only used by ulatencyd
    local mount_point = get_subsys_mount_point(subsys)
    if mount_point then
      local mounted_subsystems =
            get_mount_point_subsystems(mount_point)
      if mounted_subsystems and #mounted_subsystems > 1 then
        ulatency.log_warning(string.format(
              "Multiple cgroup subsystems (%s) mounted in"..
              " single hierarchy (%s/).",
              table.concat(mounted_subsystems, ","), mount_point ))
        crippled_subsystems = true
      end
    end
  end
  if (crippled_subsystems) then
    ulatency.log_error(
          "Multiple cgroup subsystems are mounted in single hierarchy."..
          "\nPlease, fix the application which mounted them."..
          "\nSee https://github.com/poelzi/ulatencyd/issues/49" )
  end

  -- mount all enabled subsystems
  local found_one_group = false
  local loaded_subsystems = {}
  for _,subsys in pairs(CGROUP_SUBSYSTEMS) do
    local has_subsys = ulatency.has_cgroup_subsystem(subsys)
    if has_subsys == nil then
      log_info(subsys, "Subsystem not found, disabling.")
    elseif has_subsys == false then
      log_warning(subsys,
                  "Subsystem supported by kernel, but currently disabled."..
                  " It may be enabled with a boot time parameter of Linux"..
                  " kernel `cgroup_enable=%s`%s.", subsys,
                  subsys == "memory" and " and optional `swapaccount=1`" or "")
    else
      if mount_subsystem(subsys) and mount_subsystem(subsys, true) then
        found_one_group = true
        loaded_subsystems[#loaded_subsystems+1] = subsys
        ulatency.set_tree_loaded(subsys)
        local path = CGROUP_ROOT..subsys;
        local fp = io.open(path.."/release_agent", "r")
        local ragent = fp:read("*a"):rtrim()
        fp:close()
        -- we only write a release agent if not already one. update if it
        -- looks like a ulatencyd release agent
        if ragent == "" or ragent == "\n" or
           string.sub(ragent, -21) == '/ulatencyd_cleanup.sh'
        then
          sysfs_write(path.."/release_agent", ulatency.release_agent)
          sysfs_write(path.."/notify_on_release", "1")
        else
          log_info(subsys,
                "Foreign released agent already registered: %s", ragent)
        end
      else
        log_warning(subsys, "Subsystem disabled.")
        ulatency.log_error(string.format(
              "Error occurred while trying to mount"..
              " available cgroup subsystem \"%s\".", subsys ))
      end
    end
  end

  if not found_one_group then
    ulatency.log_error("Could not found any cgroup subsystem to mount.")
  end

  ulatency.log_message(
        "Loaded cgroup subsystems: "..table.concat(loaded_subsystems, ", "))
end -- do

-------------------------------------------------------------------------------
--  End setup of cgroups subsystems
-------------------------------------------------------------------------------


-- setup root cgroup for each subsystem

for _,subsys in pairs(CGROUP_SUBSYSTEMS) do
  if ulatency.tree_loaded(subsys) then
    CGroup.new("", nil, subsys):commit()
  end
end


-- disable the autogrouping

if posix.access("/proc/sys/kernel/sched_autogroup_enabled") == 0 then
  ulatency.log_info("disable sched_autogroup in linux kernel")
  ulatency.save_sysctl("kernel.sched_autogroup_enabled", "0")
end

