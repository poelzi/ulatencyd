--[[
    Copyright 2010,2011 ulatencyd developers

    This file is part of ulatencyd.

    License: GNU General Public License 3 or later
]]--

---------------------------------
--! @file
--! @brief scheduler implementation
--! @ingroup lua_SCHEDULER
---------------------------------

require("posix")

--! @relates Scheduler
--! @brief Check if the process has a flag with one of given name.
--! @param labels Table with flag names to check (see `u_flag.name`)
--! @param proc A #u_proc instance
--! @return boolean TRUE if the #u_proc has a flag with one of `labels` names.
--! @warning don't use non alpha numeric characters in name
--! @todo build validator
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
  
  local rv = CGroup.get_group(subsys .."/".. path)
  if rv then
    return rv
  end
  
  rv = CGroup.new(path, mapping.param, subsys)
  if mapping.adjust then
    rv.adjust[#rv.adjust+1] = mapping.adjust
  end

  rv:commit()  -- force commit here to set cgroup parameters before adjust_new is run or any task added.

  if mapping.adjust_new then
    mapping.adjust_new(rv, proc)
  end
  if rv:is_dirty() then
    rv:commit()
  end
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


--! @class Scheduler
--! @implements __SCHEDULER
--! @brief This is the default %scheduler implementation.
--! For %scheduler overview see @ref lua_SCHEDULER "scheduler module". For general %scheduler interface see `__SCHEDULER`
--! table documentation.
--! @details This scheduler implementation uses a decision tree based on mapping rules. These mapping rules are stored in
--! files under `conf/scheduler/`; each of this mapping represents a scheduler configuration and only one of them can be
--! active at any time. You can choose the default one in `ulatencyd.conf` or change it runtime (via ulatency client or
--! DBUS). The default configuration (mappings) is the `desktop` stored in `conf/scheduler/20-desktop.lua`. You can
--! customise this mapping or write new one.
--! @ingroup lua_SCHEDULER
Scheduler = {
  C_FILTER = false, --!< If FALSE current iteration does not skip unchanged processes. @protected @memberof Scheduler
  ITERATION = 1, --!< Scheduler iteration (range 1 - `full_run` or 15). @protected @memberof Scheduler
  INITIALIZED = false, --!< Set by `Scheduler::_init()` on first `Scheduler::all()` execution. @protected @memberof Scheduler
  PROC_BLOCK_THRESHOLD = 1, --!< u_proc.block_scheduler threshold. @protected @memberof Scheduler
  --! Paths of cgroups left behind previous ulatencyd instance.
  --! Cgroups paths are table keys with format `<subsystem>/path`, e.g `"memory/usr_1000/default"`, value is always TRUE.
  --! @see Scheduler::load_cgroups()
  --! @protected @memberof Scheduler
  SAVED_CGROUPS = {},
  _after_hooks = {} --!< Registered `after` callbacks, see `Scheduler::register_after_hook()`. @private @memberof Scheduler
}

--! @brief Loads cgroups saved (created and not removed) by previous ulatencyd instance.
--! @detail Fills the `Scheduler.SAVED_CGROUPS` used as a hash table (cgroups paths are table keys).
--! @protected @memberof Scheduler
function Scheduler:load_cgroups()
  ulatency.log_info("scheduler: initialising - loading list of cgroups saved by previous ulatencyd instance")
  local cgroups_file = ulatency.get_config("scheduler", "cgroups_state") or "/var/run/ulatencyd/cgroups"
  self.SAVED_CGROUPS = {}
  local fp = io.open(cgroups_file)
  if not fp then
    ulatency.log_info("scheduler: initialising - list of saved cgroups does not exist: "..cgroups_file)
    return false
  end
  for cgr_path in fp:lines() do
    self.SAVED_CGROUPS[cgr_path] = true
  end
  fp:close()
  return true
end

--! @brief Saves cgroup list so it can be reuse by another future ulatencyd instance.
--! Stores list of cgroups so they can be recognised by eventual future daemon instance as beign created by ulatencyd.
--! @protected @memberof Scheduler
function Scheduler:save_cgroups()
  local success = true
  ulatency.log_info("scheduler: saving cgroups")
  self:cgroups_cleanup(true)
  local cgroups_file = ulatency.get_config("scheduler", "cgroups_state") or "/var/run/ulatencyd/cgroups"
  local parts = cgroups_file:split("/")
  local dir = table.concat(parts, "/", 1, #parts-1)
  if not mkdirp(dir) then
    success = false
  else
    local fp = io.open(cgroups_file, "w")
    if fp then
      for i,_ in pairs(CGroup.get_groups()) do
        fp:write(i..'\n')
      end
      fp:close()
    else
      if par ~= '?' then
        ulatency.log_warning("can't write into :"..tostring(path))
        success = false
      end
    end
  end
  if not success then
    ulatency.log_error("State was not saved.")
  end
  return success
end

--! @brief Initialize scheduler internals.
--! Invoked when Scheduler:all() is executed for first time.
--! - load mappings
--! - load cgroups left behind previous ulatencyd isntance (`Scheduler::load_cgroups()`)
--! - register timeout function for periodically cleaning cgroups (see `Scheduler::cgroups_cleanup()`)
--! @private @memberof Scheduler
function Scheduler:_init()
  if not self.MAPPING then
    self:load_config()
  end
  self:load_cgroups()
  local function cgroups_cleanup()
    Scheduler:cgroups_cleanup()
  end
  ulatency.add_timeout(cgroups_cleanup, 120000) --FIXME: or run this every scheduler:all() ?
end

--! @brief Registers a callback function to be run after the scheduling of process(es) is finished.
--! Use this to register callbacks from mappings rules, timeout functions, filters etc.
--! Each registered callback will be triggered from `Scheduler::all()` or `Scheduler::one()` every time scheduling is
--! finished, until the callback returns FALSE.
--! @param id Unique identification of callback function. Already registered callback with same `id` will be overwritten.
--! @param func Callback function to be run after the scheduling is finished.
--! If this function will return FALSE, it will be unregistered and not run next time.
--! @public @memberof Scheduler
function Scheduler:register_after_hook( id, func )
  self._after_hooks[id] = func
  ulatency.log_debug('Scheduler: registering after-callback with id: '..to_string(id))
end

--! @brief Runs registered callbacks after the scheduling is finished.
--! @see `Scheduler::register_after_hook()`
--! @private @memberof Scheduler
function Scheduler:_run_after_hooks()
  local callbacks = self._after_hooks
  for id,cb in pairs(callbacks) do
    ulatency.log_debug('Scheduler: run registered after-callback with id: '..to_string(id))
    if not cb() then callbacks[id]=nil end
  end
end

--! @brief Schedules all changed processes, called on every iteration.
--! @details Implements the __SCHEDULER::all() with following extensions:
--! - Schedules all processes if it has been run `full_run` times (as defined in configuration file) or 15 times since
--!   the last full run.
--! - If @link __SYSTEM_FLAG_SUSPEND `suspend`@endlink or @link __SYSTEM_FLAG_QUIT`quit`@endlink system flag is set,
--!   the `Scheduler::_quit()` is invoked with that flag passed, after processes were scheduled.
--! - If @link __SYSTEM_FLAG_CLEANUP `cleanup`@endlink system flag is set (by `Scheduler::_quit()`), the
--!   `quit` and `suspend` flags are ignored as the shutdown is already in progress.
--! @public @memberof Scheduler
function Scheduler:all()

  if not self.INITIALIZED then
    self:_init()
    self.INITIALIZED = true
  end

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
    self:_one(proc, false)
  end
  self:_run_after_hooks()
  self.C_FILTER = true
  self.ITERATION = self.ITERATION + 1

  -- detect shutdown
  for j, flag in pairs(ulatency.list_flags()) do
    if flag.name == "suspend" or flag.name == "quit" then
      self:_quit( flag )
      break
    end
  end

  return true
end

--! @brief Finishes the scheduler shutdown and quits the ulatencyd daemon.
--!
--! -# Destroys created cgroups if the name of passed flag is "quit", that is,
--!    the @link __SYSTEM_FLAG_QUIT`quit`@endlink system flag is passed.
--!   -# Tries to load `cleanup` mappings and runs `Scheduler:all()` one more time.
--! -# Saves cgroups (`Scheduler::save_cgroups()`).
--! -# Quits the daemon via without dispatching remaining main loop events (`ulatency.die()`).
--!
--! @param u_flag flag System flag that caused the shutdown.
--! @warning Do not call this function directly as filters and active scheduler mapping won't be given chance
--! to cleanup.
--! @note The preferred way of quitting ulatencyd daemon is to add `quit` or `suspend` system flag,
--! set system_flags_changed (`ulatency.set_flags_changed(1)`) and force iteration (`ulatency.run_iteration()`).
--! Or use `ulatency.quit()` for convenience. This
--! way all filters and active scheduler mappings will be given chance to react (e.g. unfreeze
--! frozen cgroups of the freezer subsystem).  Scheduler will then call this function with the
--! guilty system flag passed as argument.
--! @private @memberof Scheduler
function Scheduler:_quit(flag)
  if flag then
    ulatency.del_flag(flag)
    if flag.name == "quit" then
      -- cleanup cgroups
      ulatency.log_info("scheduler: cleaning up")
      if self:load_config("cleanup") then
      self.PROC_BLOCK_THRESHOLD = 2   --cleanup cgroups with blocked processes
        ulatency.set_flags_changed(1)
        self:all() -- cleanup round with "cleanup" scheduler config
      else
        ulatency.log_warning("Could not switch to cleanup mapping. CGroups are not cleaned up!")
      end
    end
  end
  self:save_cgroups()
  ulatency.die(flag.threshold or flag.name == "suspend" and 1 or 0)
end

--! @public @memberof Scheduler
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
  ulatency.log_debug("use scheduler map \n" .. to_string(MAPPING))
  self.MAPPING = MAPPING
  self.CONFIG_NAME = name
  return true
end

--! @protected @memberof Scheduler
function Scheduler:update_caches()
  Scheduler.meminfo = ulatency.get_meminfo()
  Scheduler.vminfo = ulatency.get_vminfo()
end

--! Schedules one process, a wrapper around `Scheduler::_one()`
--! @public @memberof Scheduler
function Scheduler:one(proc)
  return self:_one(proc, true)
end

--! @private @memberof Scheduler
function Scheduler:_one(proc, single)
  if not self.MAPPING then
    self:load_config()
  end

  if single then
    self:update_caches()
  end

  local group
  if proc.block_scheduler < self.PROC_BLOCK_THRESHOLD then
    local cgr_paths, cgroups = proc:get_cgroups()
    for x,subsys in ipairs(ulatency.get_cgroup_subsystems()) do
      map = self.MAPPING[subsys] or SCHEDULER_MAPPING_DEFAULT[subsys]
      if map and ulatency.tree_loaded(subsys) then

        -- skip foreign cgroups
        local cgr_name = subsys .. cgr_paths[subsys]
        if not (cgr_paths[subsys] == "/" or cgroups[subsys] or self.SAVED_CGROUPS[cgr_name]) then
          ulatency.log_info(string.format("scheduler subsys %s: skippping %s (pid: %d) because its cgroup %s is foreign",
            subsys, proc.cmdfile or "unknown", proc.pid or -1, cgr_name))
        else

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
    end
    proc:clear_changed()
    --pprint(build_path_parts(proc, res))
  end
  if single then
      self:_run_after_hooks()
  end
  return true
end

--! @public @memberof Scheduler
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

--! @public @memberof Scheduler
function Scheduler:get_config_description(name)
  name = string.upper(name)
  local mapping = getfenv()["SCHEDULER_MAPPING_" .. name]
  if mapping and mapping.info then
    return mapping.info.description
  end
end

--! @public @memberof Scheduler
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

--! @public @memberof Scheduler
function Scheduler:get_config()
  if self.CONFIG_NAME then
    return string.lower(self.CONFIG_NAME)
  end
  return nil
end

-- cgroups cleanup
local CGROUPS_CLEANUP_SCHEDULED = false
local function _cgroups_cleanup()
  ulatency.log_debug("Scheduler: cleaning cgroups.")
  local to_preserve, to_remove = {}, {}
  local groups = CGroup.get_groups()
  CGROUPS_CLEANUP_SCHEDULED = false

  for n, c in pairs(groups) do
    if c:can_be_removed() then
      to_remove[#to_remove + 1] = n
    else
      to_preserve[#to_preserve + 1] = n .. "/"
    end
  end
  local remove = {}
  for i,r_grp in ipairs(to_remove) do
    local needed = false
    for _, p_grp in ipairs(to_preserve) do
      if string.sub(p_grp .. "/", 1, #r_grp) == r_grp then
        to_remove[i] = nil
        break
      end
    end
    remove[#remove+1] = { #r_grp:split("/"), r_grp }
  end
  table.sort(remove, function(a,b) return a[1] > b[1] end)
  for _,v in ipairs(remove) do
    if groups[v[2]]:remove() then
      groups[v[2]] = nil
    end
  end
end

--! @public @memberof ulatency
function Scheduler:cgroups_cleanup(instant)
  if not self.INITIALIZED then return end
  if instant then
    _cgroups_cleanup()
  elseif not CGROUPS_CLEANUP_SCHEDULED then
    CGROUPS_CLEANUP_SCHEDULED = true
    ulatency.add_timeout(_cgroups_cleanup, 2000)
  end
end

--! @brief scheduler instance
--! @public @memberof ulatency
ulatency.scheduler = Scheduler

ulatency.load_rule_directory("scheduler/")