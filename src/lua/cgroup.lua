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
    local fp, errmsg = io.open(t_file, "w")
    if fp == nil then
      ulatency.log_warning("Cannot add new task(s) to cgroup: "..errmsg)
    else
      fp:setvbuf("no")

      ulatency.log_sched("Move to "..tostring(self).." tasks: "..table.concat(pids, ","))

      -- move PIDs to cgroup
      for i, pid in ipairs(pids) do
        local ok, err, err_code = fp:write(tostring(pid)..'\n')
        if not ok then
          if ulatency.is_pid_alive(pid) then --suppress warning if the task is already dead
            sysfs_write_error(t_file, tostring(pid), err, err_code)
          end
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

--! @} End of "addtogroup lua_CGROUPS"

