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
--! @ingroup lua_CORE lua_CGROUPS
--! @brief ulatencyd cgroup  table
-------------------------------------------------------------------------------

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
  local default = (name == "") and
                  CGROUP_ROOT_DEFAULT[tree] or CGROUP_DEFAULT[tree]
  local cinit = default and table.copy(default) or {}
  local uncommited = table.merge(cinit, init or {})
  local rv = setmetatable( {name=name, uncommited=uncommited, new_tasks={},
                            tree=tree, adjust={}, used=false}, CGroupMeta)
  _CGroup_Cache[tree..'/'..name] = rv
  ulatency.log_sched("New cgroup created: "..tostring(rv))
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

--! Get value of cgroup parameter `key`.
--! @param key Name of the cgroup parameter.
--! @param raw If true then always read the current value from file `key`.
--! @param row_format If `raw` is true then this specifies the format for
--! file:read(). If nil given, the default format "*l" is used.
--! @retval value of `key`
--! @retval nil If no data could be read with specified `raw_format`.
--! @retval nil, errstr, errno If the `key` file cannot be opened.
--! @public @memberof CGroup
function CGroup:get_value(key, raw, raw_format)
  if not raw then
    local uncommited = rawget(self, "uncommited")
    if uncommited[key] then
      return uncommited[key]
    end
  end
  local path = self:path(key)
  local ok, errstr, errno = posix.access(path)
  local fp
  if ok then
    fp, errstr, errno = io.open(path, "r")
    if fp then
      return fp:read(raw_format or "*l")
    end
  else
    return nil, errstr, errno
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


--! @retval true
--! @retval nil, errstr, errno
--! @public @memberof CGroup
function CGroup:commit(quiet)
  local ok, errstr, errno

  ok, errstr, errno = mkdirp(self:path(), quiet)
  if ok then
    ok, errstr, errno = mkdirp(self:private_path(), quiet)
  end
  if not ok then
    return nil, errstr, errno
  end

  local quiet_param = quiet
  local uncommited = rawget(self, "uncommited")
  for k, v in pairs(uncommited) do
    if string.sub(k, 1, 1) == '?' then
      quiet_param = true
      k = string.sub(k, 2)
    end
    local path = self:path(k)
    ok, errstr, errno = sysfs_write(path, v, quiet_param)
    if ok or quiet_param then
      uncommited[k] = nil
    end
  end

  local pids = rawget(self, "new_tasks")
  if #pids > 0 then
    local t_file = self:path("tasks")
    local fp, t_errstr, t_errno = io.open(t_file, "w")
    if fp == nil then
      if not quiet then
        ulatency.log_warning(string.format(
              "Cannot add new task(s) to %s: (%d) %s",
               tostring(self), t_errno, t_errstr ))
        end
        return nil, t_errstr, t_errno
    end

    ulatency.log_sched("Move to "..tostring(self).." tasks: "..table.concat(pids, ","))

    -- move PIDs to cgroup
    fp:setvbuf("no")
    for i, pid in ipairs(pids) do
      local t_ok, t_errstr, t_errno = fp:write(tostring(pid)..'\n')
      if not t_ok then
        if not quiet and ulatency.is_pid_alive(pid) then
          sysfs_write_error(t_file, tostring(pid), t_errstr, t_errno)
        end
        ok, errstr, errno = t_ok, t_errstr, t_errno
      else
        local proc = ulatency.get_pid(pid)
        if proc then
          proc:set_cgroup(self.tree, "/".. self.name)
        end
      end
    end

    rawset(self, "new_tasks", {})
    fp:close()
  end

  return ok and true or nil, errstr, errno
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
  local cgr_name = "iso_"..(suffix or tostring(pid))
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
        ulatency.log_info(string.format('Isolation group %s created.', ng:path()))
      end
      ulatency.log_sched(string.format(
              'Move pid %d, cmdfile %s, exe %s" with tasks %s to isolation group %s.',
               proc.pid, proc.cmdfile or "NONE", proc.exe or "NONE",
               table.concat(tasks,','),
               ng:path()))
      ng:run_adjust(proc)
      ng:add_task_list(proc.pid, tasks)
      if include_children then
        ng:add_children(proc)
      end
      ng:commit()
    end
  end

  local block = block_scheduler or 1
  local block_reason = "it is flagged for isolation in cgroup "..cgr_name
  local proc_fnc = function(proc)
    if fnc then fnc(proc) end
    proc:set_block_scheduler(block, block_reason)
  end
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


-------------------------------------------------------------------------------
-- Begin detecting ranges of parameters values accepted by cgroup subsystems
-------------------------------------------------------------------------------

--! @retval min, max
--! @retval nil, nil, errstr, errno
local function detect_cgroup_key_range(subsys, key, range_min, range_max)
  local min, max = tonumber(range_min), tonumber(range_max)
  if not min then return nil, nil, "Wrong minimum of range: "..range_min, -1 end
  if not max then return nil, nil, "Wrong maximum of range: "..range_max, -1 end
  if not ulatency.tree_loaded(subsys) then
    return nil, nil, subsys.." subsys not loaded.", -2
  end

  local cgr = CGroup.new("test."..key, nil, subsys)
  local ok, errstr, errno = cgr:commit(true)
  if not ok then
    cgr:remove()
    return nil, nil, errstr, errno
  end

  -- get current value, will be use as min/max value for binary search
  local initval, errstr, errno = cgr:get_value(key, true)
  if not initval then
    cgr:remove()
    return nil, nil, errstr, errno
  end
  initval = tonumber(initval)
  if not initval then
    cgr:remove()
    return nil, "Initial cgroup value not a number.", -3
  end

  local check = function(value)
    cgr:set_value(key, value)
    if cgr:commit(true) then
      return tonumber(cgr:get_value(key, true)) == value and true or false
    end
    return false
  end

  local search = function(min, max, dir) -- binary search
    local rv = dir == "up" and min or max
    local s, e, m = min, max
    while s <= e do
      m = math.floor((s+e)/2)
      if check(m) then
        rv = m
        if dir == "up" then s = m + 1 else e = m - 1 end
      else
        if dir == "up" then e = m - 1 else s = m + 1 end
      end
    end
    return rv
  end

  -- search
  local _min = check(min) and min or search(min+1, initval, "down")
  local _max = check(max) and max or search(initval, max-1, "up")
  cgr:remove()
  return _min, _max
end

--
-- Range of values allowed for cgroups parameters.
--
-- { <subsystem> = { <parameter> = {<min>, <max>}, ..}, ..}
--
-- The interval <min,max> validity is in an empty cgroup. If the test fails,
-- nearest narrower interval is calculated and used.
-- If the third range value is true, the range validity is not tested.
local __CGROUP_KEYS_RANGES = {            -- {min, max, force}
  cpu =   {
            ["cpu.shares"]                 = {2, 262144},
  },
  blkio = {
            ["blkio.weight"]               = {10, 1000},
  },
  bfqio = {
            ["bfqio.weight"]               = {1, 1000},
  },
}

--! initialize __CGROUP_KEYS_RANGES table
function CGroup.init_key_ranges(die_on_error)
  for subsys, def in pairs(__CGROUP_KEYS_RANGES) do
    if not ulatency.tree_loaded(subsys) then
      for param, _ in pairs(def) do
        __CGROUP_KEYS_RANGES[subsys][param] = {nil, nil}
      end
    else
      for param, range in pairs(def) do
        local min, max = tonumber(range[1]), tonumber(range[2])
        local force = range[3]
        if force then
          __CGROUP_KEYS_RANGES[subsys][param] = {min, max}
          ulatency.log_debug(string.format(
                "subsys %s: Using forced range for parameter %s = {%d, %d}",
                subsys, param, min, max))
        else -- force
          local min, max, errstr, errno =
                detect_cgroup_key_range(subsys, param, min, max)
          if min and max then
            __CGROUP_KEYS_RANGES[subsys][param] = {min, max}
            ulatency.log_debug(string.format(
                  "subsys %s: Detected range for parameter %s = {%d, %d}",
                  subsys, param, min, max))
          else
            ulatency.log(die_on_error and ulatency.LOG_LEVEL_ERROR or
                  ulatency.LOG_LEVEL_WARNING, string.format(
                  "subsys %s: Range of values for %s parameter could not be "..
                  "detected. Parameter will not be used. Error code %d: %s",
                  subsys, param, errno, errstr ))
          end
        end -- else force
      end
    end
  end
end

--! Return range of cgroup parameter `key`
--! @param self #CGroup instance or subsystem string
--! @param key Name of cgroup parameter
--! @retval min, max
--! @retval nil, nil If the range was not detected or `key` is not recalcable;
--! see `CGroup.is_recalcable`
--! @public @memberof CGroup
function CGroup.get_key_range(self, key)
  local subsys = type(self) == "string" and self or self.tree
  if string.sub(key, 1, 1) == '?' then key = string.sub(key, 2) end

  if __CGROUP_KEYS_RANGES[subsys] and __CGROUP_KEYS_RANGES[subsys][key] then
    return  __CGROUP_KEYS_RANGES[subsys][key][1],
            __CGROUP_KEYS_RANGES[subsys][key][2]
  else
    return nil, nil
  end
end

function CGroup.is_recalcable_key(self, key)
  local subsys = type(self) == "string" and self or self.tree
  if string.sub(key, 1, 1) == '?' then key = string.sub(key, 2) end

  return __CGROUP_KEYS_RANGES[subsys] and
         __CGROUP_KEYS_RANGES[subsys][key]
end

--! @param self #CGroup instance or subsystem string
--! @retval recalculated_number
--! @retval nil
function CGroup.get_recalc_value(self, key, value)
  if not CGroup.is_recalcable_key(self, key) then return value end

  local subsys = type(self) == "string" and self or self.tree
  if string.sub(key, 1, 1) == '?' then key = string.sub(key, 2) end

  local min, max = CGroup.get_key_range(subsys, key)
  if not (min and max) then return nil end

  local number = tonumber(value)
  if number then
    return number < min and min or number > max and max or number
  else
    -- string
    value = value:upper()
    if value == "MAX" then return max end
    if value == "MIN" then return min end
    if value:sub(-1) == '%' then
      value = tonumber(value:sub(1, -2))
      if value then return (max - min) / 100 * value
      else
        ulatancy.log_warning(string.format(
              "subsys %s: Wrong value for cgroup parameter %s: %s",
              subsys, key, value ))
        return nil
      end
    end
  end
  return value
end


-------------------------------------------------------------------------------
-- End detecting ranges of parameters values accepted by cgroup subsystems
-------------------------------------------------------------------------------

--! @} End of "addtogroup lua_CGROUPS"
