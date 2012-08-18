--! @brief Utility functions for Scheduler mappings
--! @file
--! @ingroup lua_CORE

--! @brief Saves I/O scheduling class and priority of process `#U_PROC` and sets new values.
--! @param proc a process `#U_PROC` instance
--! @param prio I/O scheduling priority
--! @param prio I/O scheduling class
--! @see `U_PROC::set_ioprio()` for parameters description.
--! @see lua_PROC_SCHED
--! @ingroup lua_PROC_SCHED
--! @relates #U_PROC
function save_io_prio(proc, prio, class)
  if not proc.data.io_prio then
    proc.data.io_prio = {proc:get_ioprio()}
  end
  proc:set_ioprio(prio, class)
end

--! @brief Restore saved I/O scheduling class and priority of process `#U_PROC`.
--! Restores values previously saved by `save_io_prio()`.
--! @param proc a process `#U_PROC` instance
--! @ingroup lua_PROC_SCHED
--! @relates #U_PROC
function restore_io_prio(proc)
  if proc.data.io_prio then
    local pr = proc.data.io_prio
    proc:set_ioprio(pr[1], pr[2])
  end
end

function merge_config(template, new_values)
  rv = {}
  if new_values.pre then
    for k,entry in ipairs(new_values.pre) do
      rv[#rv+1] = entry
    end
  end
  local offset = #rv
  if new_values.replace then
    for k,entry in pairs(template) do
      rv[offset+k] = entry
      for nkey,nvalue in pairs(new_values.replace) do
        if nvalue.name == entry.name then
          rv[offset+k] = nvalue
        end
      end
    end
  end
  if new_values.post then
    for k,entry in ipairs(new_values.post) do
      rv[#rv+1] = entry
    end
  end
  return rv
end


-- fallback mappings
SCHEDULER_MAPPING_DEFAULT = {}

SCHEDULER_MAPPING_DEFAULT["cpuset"] =
{
    {
      name = "",
      cgroups_name = "",
      check = function(proc) return true end,
    },
}
