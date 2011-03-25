--[[
    Copyright 2010,2011 ulatencyd developers

    This file is part of ulatencyd.

    License: GNU General Public License 3 or later
]]--

require("posix")

u_groups = {}


local UL_PID = posix.getpid()["pid"]

ul_group_cpu = CGroup.new("s_ul", { ["cpu.shares"]="500"}, "cpu")
ul_group_cpu:add_task(UL_PID)
ul_group_cpu:commit()
ul_group_mem = CGroup.new("s_ul", { ["?memory.swappiness"]="0"}, "memory")
ul_group_cpu:add_task(UL_PID)
ul_group_cpu:commit()


-- WARNING: don't use non alpha numeric characters in name
-- FIXME: build validator

function check_label(labels, proc)
  for j, flag in pairs(proc:list_flags(true)) do
    for k, slabel in pairs(labels) do
      if flag.name == slabel then
        return true
      end
    end
  end
end

local function check(proc, rule)
  assert(proc)
  if rule.label then
    if check_label(rule.label, proc) then
      if rule.check then
        return rule.check(proc) and rule or nil
      else
        return rule
      end
    end
  elseif rule.check then
    if rule.check(proc) then
      return rule
    end
  end
  return nil
end

local function run_list(proc, lst)
  local rv = {}
  for key, rule in ipairs(lst) do
    match = check(proc, rule)
    if match then
      rv[#rv+1] = match
      if match.children then
        best_subs = run_list(proc, match.children)
        --print("got bestsubs", type(best_subs), best_subs, #best_subs)
        if best_subs and #best_subs > 0 then
          for i,sub in ipairs(best_subs) do
            rv[#rv+1] = sub
          end
        end
      end
      break
    end
  end
  return rv
end

local function format_name(proc, map)
  -- generates the final path for the process for the map
  if map.cgroups_name then
    if type(map.cgroups_name) == "function" then
      return map.cgroups_name(proc)
    end
    function get(name)
      return tostring(proc[name])
    end
    return string.gsub(map.cgroups_name, "%$\{(%w+)\}", get)
  end
  return map.name
end

local function build_path_parts(proc, res)
  -- build a array for 
  local rv = {}
  for i,k in ipairs(res) do
    local cname = format_name(proc, k)
    rv[#rv+1] = cname
  end
  return rv
end

local function create_group(proc, prefix, mapping, subsys)
  name = format_name(proc, mapping)
  if #prefix > 0 then
    path = prefix .. "/" .. name
  else
    path = name
  end
  rv = CGroup.new(path, mapping.param, subsys)
  if mapping.adjust then
    rv.adjust[#rv.adjust+1] = mapping.adjust
  end

  if mapping.adjust_new then
    mapping.adjust_new(rv, proc)
  end
  rv:commit()
  return rv
end

local function map_to_group(proc, parts, subsys)
  local chain = build_path_parts(proc, parts)
  local path = subsys .."/".. table.concat(chain, "/")
  local cgr = CGroup.get_group(path)
  if cgr then
    cgr:run_adjust(proc)
    return cgr
  end

  local prefix = ""
  for i, parrule in ipairs(parts) do
    --local parent = create_group(proc, prefix, 
    cgr = create_group(proc, prefix, parrule, subsys)
    prefix = cgr.name
  end
  --print("final prefix", prefix)
  --CGroup.new(mapping.name, )n-ar
  return cgr
end


Scheduler = {C_FILTER = false, ITERATION = 1}

function Scheduler:all()
  local group
  if ulatency.get_flags_changed() then
    self.C_FILTER = false
  end
  for j, flag in pairs(ulatency.list_flags()) do
    if flag.name == "pressure" or flag.name == "emergency" then
      self.C_FILTER = false
    end
  end
  if self.ITERATION > (tonumber(ulatency.get_config("scheduler", "full_run") or 15)) then
    self.C_FILTER = false
    self.ITERATION = 1
  end
  -- list only changed processes
  self:update_caches()

  ulatency.log_debug("scheduler filter:".. tostring(self.C_FILTER))
  for k,proc in ipairs(ulatency.list_processes(self.C_FILTER)) do
    --print("sched", proc, proc.cmdline)
    self:one(proc, false)
  end
  self.C_FILTER = true
  self.ITERATION = self.ITERATION + 1
  return true
end


function Scheduler:load_config(name)
  if not name then
    name = ulatency.get_config("scheduler", "mapping")
    if not name then
      ulatency.log_error("no default scheduler config specified in config file")
    end
  end
  ulatency.log_info("Scheduler use mapping: "..name)
  local mapping_name = "SCHEDULER_MAPPING_"..string.upper(name)
  MAPPING = getfenv()[mapping_name]
  if not MAPPING then
    if not self.MAPPING then
      ulatency.log_error("invalid mapping: "..mapping_name)
    else
      ulatency.log_warning("invalid mapping: "..mapping_name)
    end
    return false
  end
  ulatency.log_debug("use schduler map \n" .. to_string(MAPPING))
  self.MAPPING = MAPPING
  self.CONFIG_NAME = name
  return true
end

function Scheduler:update_caches()
  Scheduler.meminfo = ulatency.get_meminfo()
  Scheduler.vminfo = ulatency.get_vminfo()
end

function Scheduler:one(proc)
  return self:_one(proc, true)
end

function Scheduler:_one(proc, single)
  if not self.MAPPING then
    self:load_config()
  end

  if single then
    self:update_caches()
  end

  if proc.block_scheduler == 0 then
    -- we shall not touch us
    if proc.pid == UL_PID then
      proc:clear_changed()
      return true
    end
    for subsys,map in pairs(self.MAPPING) do
      if ulatency.tree_loaded(subsys) then
        local mappings = run_list(proc, map)
        --pprint(mappings)
        group = map_to_group(proc, mappings, subsys)
        --print(tostring(group))
        --pprint(mappings)
        --print(tostring(proc.pid) .. " : ".. tostring(group))
        if group then
          if group:is_dirty() then
            group:commit()
          end
          --print("add task", proc.pid, group)
          -- get_current_tasks can fail if the process is already dead
          local tasks = proc:get_current_task_pids(true)
          if tasks then
            group:add_task_list(proc.pid, tasks)
            group:commit()
          end
        else
          ulatency.log_debug("no group found for: "..tostring(proc).." subsystem:"..tostring(subsys))
        end
      end
    end
    proc:clear_changed()
    --pprint(build_path_parts(proc, res))
  end
  return true
end

function Scheduler:list_configs()
  rv = {}
  for k,v in pairs(getfenv()) do
    if string.sub(k, 1, 18 ) == "SCHEDULER_MAPPING_" then
      name = string.lower(string.sub(k, 19))
      if v.info then
        if not v.info.hidden then
          rv[#rv+1] = name
        end
      else
        rv[#rv+1] = name
      end
    end
  end
  return rv
end

function Scheduler:get_config_description(name)
  name = string.upper(name)
  local mapping = getfenv()["SCHEDULER_MAPPING_" .. name]
  if mapping and mapping.info then
    return mapping.info.description
  end
end

function Scheduler:set_config(config)
  if ulatency.get_config("scheduler", "allow_reconfigure") ~= 'true' then
    ulatencyd.log_info("requested scheduler reconfiguration denied")
    return false
  end
  local rv = self:load_config(config)
  if rv then
    self.C_FILTER = false
    ulatency.run_iteration()
  end
  return rv
end

function Scheduler:get_config()
  if self.CONFIG_NAME then
    return string.lower(self.CONFIG_NAME)
  end
  return nil
end

-- register scheduler
ulatency.scheduler = Scheduler

ulatency.load_rule_directory("scheduler/")