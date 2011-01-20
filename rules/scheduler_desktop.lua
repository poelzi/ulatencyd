--[[
    Copyright 2010,2011 ulatencyd developers

    This file is part of ulatencyd.

    License: GNU General Public License 3 or later
]]--

SCHEDULER_MAPPING_DESKTOP = {}
-- cpu & memory configuration
SCHEDULER_MAPPING_DESKTOP["cm"] =
{
  {
    name = "system_essential",
    cgroups_name = "sys_essential",
    param = { ["cpu.shares"]="3048" },
    label = { "system.essential" }
  },
  {
    name = "user",
    cgroups_name = "usr_${euid}",
    check = function(proc)
              return ( proc.euid > 999 )
            end,
    param = { ["cpu.shares"]="3048" },
    children = {
      { 
        name = "poison",
        param = { ["cpu.shares"]="10" },
        label = { "user.poison" },
        cgroups_name = "psn_${pid}",
        check = function(proc)
                  return true
                end,
        adjust = function(cgroup, proc)
                end,
        adjust_new = function(cgroup, proc)
                  cgroup:add_task(proc.pid)
                  cgroup:commit()
                  bytes = cgroup:get_value("memory.usage_in_bytes")
                  if not bytes then
                    ulatency.log_warning("can't access memory subsystem")
                    return
                  end
                  bytes = math.floor(bytes*(tonumber(ulatency.get_config("memory", "process_downsize")) or 0.95))
                  cgroup:set_value("memory.soft_limit_in_bytes", bytes)
                  cgroup:commit()
                end
      },
      { 
        name = "poison_group",
        param = { ["cpu.shares"]="300" },
        cgroups_name = "pgr_${pgrp}",
        check = function(proc)
                  local rv = ulatency.find_flag(ulatency.list_flags(), {name = "user.poison.group",
                                                                    value = proc.pgrp})
                  return rv ~= nil
                end,
        adjust_new = function(cgroup, proc)
                  local flag = ulatency.find_flag(ulatency.list_flags(), 
                                                    { name = "user.poison.group",
                                                      value = proc.pgrp })
                  cgroup:add_task(proc.pid)
                  cgroup:set_value("memory.soft_limit_in_bytes", flag.threshold)
                  cgroup:commit()
                end
      },
      { 
        name = "bg_high",
        param = { ["cpu.shares"]="1000" },
        label = { "user.bg_high" },
      },
      { 
        name = "media",
        param = { ["cpu.shares"]="2600" },
        label = { "user.media" },
      },
      { 
        name = "ui",
        param = { ["cpu.shares"]="2000" },
        label = { "user.ui" }
      },
      { 
        name = "active",
        param = { ["cpu.shares"]="1500" },
        check = function(proc)
            return proc.is_active
          end
      },
      { 
        name = "idle",
        param = { ["cpu.shares"]="200" },
      },
      { 
        name = "group",
        param = { ["cpu.shares"]="600" },
        cgroups_name = "grp_${pgrp}",
        check = function(proc)
                  return true
                end,
      },
    },
  },
  {
    name = "system",
    cgroups_name = "sys_idle",
    label = { "daemon.idle" },
    param = { ["cpu.shares"]="1" },
  },
  {
    name = "system",
    cgroups_name = "sys_bg",
    label = { "daemon.bg" },
    param = { ["cpu.shares"]="600" },
  },
  {
    name = "system",
    cgroups_name = "sys_daemon",
    check = function(proc)
              -- don't put kernel threads into a cgroup
              return (proc.ppid ~= 0 or proc.pid == 1)
            end,
    param = { ["cpu.shares"]="800" },
  },
}

-- io configuration. blkio does not support hirarchies
SCHEDULER_MAPPING_DESKTOP["io"] =
{
  { 
    name = "active",
    param = { ["blkio.weight"]="1000" },
    check = function(proc)
        return proc.is_active
      end
  },
  { 
    name = "group",
    param = { ["blkio.weight"]="300" },
    cgroups_name = "ps_${pgrp}",
    check = function(proc)
              return proc.pgrp > 0
            end,
  }, { 
    name = "kernel",
    cgroups_name = "",
    check = function(proc)
              return true
            end
  },
}
