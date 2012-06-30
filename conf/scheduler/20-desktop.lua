--[[
    Copyright 2010,2011 ulatencyd developers

    This file is part of ulatencyd.

    License: GNU General Public License 3 or later
]]--

SCHEDULER_MAPPING_DESKTOP = {
  info = {
    description = "a good default desktop configuration"
  }
}


-- cpu & memory configuration
SCHEDULER_MAPPING_DESKTOP["cpu"] =
{
  {
    name = "rt_tasks",
    cgroups_name = "rt_tasks",
    param = { ["cpu.shares"]="3048", ["?cpu.rt_runtime_us"] = "949500" },
    check = function(proc)
          local rv = proc.received_rt or check_label({"sched.rt"}, proc) or proc.vm_size == 0
          -- note: some kernel threads cannot be moved to cgroup, ie. migration/0 and watchdog/0
          return rv
        end,
  },
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
    param = { ["cpu.shares"]="3048",  ["?cpu.rt_runtime_us"] = "100" },
    children = {
      { 
        name = "poison",
        param = { ["cpu.shares"]="10" },
        label = { "user.poison" },
        cgroups_name = "psn_${pid}",
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
      },
      { 
        name = "bg_high",
        param = { ["cpu.shares"]="1000",  ["?cpu.rt_runtime_us"] = "1"},
        label = { "user.bg_high" },
      },
      { 
        name = "media",
        param = { ["cpu.shares"]="2600", ["?cpu.rt_runtime_us"] = "1"},
        label = { "user.media" },
      },
      { 
        name = "ui",
        param = { ["cpu.shares"]="2000", ["?cpu.rt_runtime_us"] = "1"},
        label = { "user.ui" }
      },
      { 
        name = "active",
        param = { ["cpu.shares"]="1500", ["?cpu.rt_runtime_us"] = "1"},
        check = function(proc)
            return proc.is_active
          end
      },
      { 
        name = "idle",
        param = { ["cpu.shares"]="200"},
        label = { "user.idle" },
      },
      { 
        name = "group",
        param = { ["cpu.shares"]="600", ["?cpu.rt_runtime_us"] = "1"},
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
    param = { ["cpu.shares"]="1"},
  },
  {
    name = "system",
    cgroups_name = "sys_bg",
    label = { "daemon.bg" },
    param = { ["cpu.shares"]="600"},
  },
  {
    name = "system",
    cgroups_name = "sys_daemon",
    check = function(proc)
              -- don't put kernel threads into a cgroup
              return (proc.pgrp > 0)
            end,
    param = { ["cpu.shares"]="800",
              ["?cpu.rt_runtime_us"] = "1"},
  }
}

SCHEDULER_MAPPING_DESKTOP["memory"] =
{
  {
    name = "system_essential",
    cgroups_name = "sys_essential",
    param = { ["?memory.swappiness"] = "0" },
    label = { "system.essential" }
  },
  {
    name = "user",
    cgroups_name = "usr_${euid}",
    check = function(proc)
              return ( proc.euid > 999 )
            end,
    children = {
      { 
        name = "poison",
        label = { "user.poison" },
        cgroups_name = "psn_${pid}",
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
                  -- we use soft limit, but without limit we can't set the memsw limit
                  local max_rss = math.floor(num_or_percent(ulatency.get_config("memory", "max_rss"),
                                                 Scheduler.meminfo.kb_main_total,
                                                 false) * 1024)
                  local total_limit = math.max(math.floor(num_or_percent(ulatency.get_config("memory", "total_limit"), 
                                                   Scheduler.meminfo.kb_main_total + Scheduler.meminfo.kb_swap_total) * 1024),
                                               max_rss)
                  ulatency.log_info("memory container created: ".. cgroup.name .. " max_rss:" .. tostring(max_rss) .. " max_total:" .. tostring(total_limit) .. " soft_limit:".. tostring(bytes))
                  cgroup:set_value("memory.limit_in_bytes", max_rss)
                  cgroup:set_value("memory.memsw.limit_in_bytes", total_limit, max_rss)
                  cgroup:commit()
                end
      },
      { 
        name = "poison_group",
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
                  cgroup:set_value("memory.soft_limit_in_bytes", math.ceil(flag.threshold*(tonumber(ulatency.get_config("memory", "group_downsize") or 0.95))))
                  -- we use soft limit, but without limit we can't set the memsw limit
                  local max_rss = math.floor(num_or_percent(ulatency.get_config("memory", "max_rss"),
                                                 Scheduler.meminfo.kb_main_total,
                                                 false) * 1024)
                  local total_limit = math.max(math.floor(num_or_percent(ulatency.get_config("memory", "total_limit"), 
                                                   Scheduler.meminfo.kb_main_total + Scheduler.meminfo.kb_swap_total) * 1024),
                                               max_rss)
                  ulatency.log_info("memory container created: ".. cgroup.name .. " max_rss:" .. tostring(max_rss) .. " max_total:" .. tostring(total_limit) .. " soft_limit:".. tostring(bytes))
                  cgroup:set_value("memory.limit_in_bytes", max_rss)
                  cgroup:set_value("memory.memsw.limit_in_bytes", total_limit, max_rss)
                  cgroup:commit()
                end
      },
      { 
        name = "bg_high",
        param = { ["?memory.swappiness"] = "20" },
        label = { "user.bg_high" },
      },
      { 
        name = "media",
        param = { ["?memory.swappiness"] = "40" },
        label = { "user.media" },
      },
      { 
        name = "ui",
        param = { ["?memory.swappiness"] = "0" },
        label = { "user.ui" }
      },
      { 
        name = "active",
        param = { ["?memory.swappiness"] = "0" },
        check = function(proc)
            return proc.is_active
          end
      },
      { 
        name = "idle",
        param = { ["?memory.swappiness"] = "100" },
      },
      { 
        name = "group",
        param = {["?memory.swappiness"] = "60" },
        cgroups_name = "default",
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
    param = { ["?memory.swappiness"] = "100" },
  },
  {
    name = "system",
    cgroups_name = "sys_bg",
    label = { "daemon.bg" },
    param = { ["?memory.swappiness"] = "100" },
  },
  { 
    name = "kernel",
    cgroups_name = "",
    check = function(proc)
    		  -- don't put kernel threads into a cgroup
              return (proc.vm_size == 0)
            end
  },
  {
    name = "system",
    cgroups_name = "sys_daemon",
    check = function(proc)
    		  return true
            end,
    param = { ["?memory.swappiness"] = "70" },
  },
}


-- io configuration. blkio does not support hirarchies
SCHEDULER_MAPPING_DESKTOP["blkio"] =
{
  {
    name = "poison",
    label = { "user.poison", "user.poison.group" },
    cgroups_name = "psn_${pgrp}",
    param = { ["blkio.weight"]="1" },
    adjust = function(cgroup, proc)
                save_io_prio(proc, 7, ulatency.IOPRIO_CLASS_IDLE)
             end,
  },
  {
    name = "active",
    cgroups_name = "usr_${euid}_active",
    param = { ["blkio.weight"]="1000" },
    check = function(proc)
        return proc.is_active
      end,
    adjust = function(cgroup, proc)
                save_io_prio(proc, 3, ulatency.IOPRIO_CLASS_BE)
             end,
  },
  { 
    name = "ui",
    label = { "user.ui" },
    adjust = function(cgroup, proc)
                save_io_prio(proc, 2, ulatency.IOPRIO_CLASS_BE)
             end,
  },
  {
    name = "idle",
    param = { ["blkio.weight"]="1" },
    label = { "daemon.idle", "user.idle" },
    adjust = function(cgroup, proc)
                save_io_prio(proc, 5, ulatency.IOPRIO_CLASS_IDLE)
             end,
  },
  {
    name = "media",
    param = { ["blkio.weight"]="300" },
    cgroups_name = "grp_${pgrp}",
    label = { "user.media"},
    adjust = function(cgroup, proc)
                save_io_prio(proc, 7, ulatency.IOPRIO_CLASS_RT)
             end,
  },
  {
    name = "group",
    param = { ["blkio.weight"]="300" },
    cgroups_name = "grp_${pgrp}",
    check = function(proc)
              return proc.pgrp > 0
            end,
    adjust = function(cgroup, proc)
                restore_io_prio(proc)
             end,
  },
  {
    name = "kernel",
    cgroups_name = "",
    check = function(proc)
              return (proc.vm_size == 0)
            end
  },
}

SCHEDULER_MAPPING_DESKTOP["bfqio"] =
{
  {
    name = "poison",
    label = { "user.poison", "user.poison.group" },
    cgroups_name = "psn_${pgrp}",
    param = { ["bfqio.weight"]="1" },
    adjust = function(cgroup, proc)
                save_io_prio(proc, 7, ulatency.IOPRIO_CLASS_IDLE)
             end,
  },
  {
    name = "active",
    cgroups_name = "usr_${euid}_active",
    param = { ["bfqio.weight"]="1000" },
    check = function(proc)
        return proc.is_active
      end,
    adjust = function(cgroup, proc)
                save_io_prio(proc, 3, ulatency.IOPRIO_CLASS_BE)
             end,
  },
  { 
    name = "ui",
    label = { "user.ui" },
    adjust = function(cgroup, proc)
                save_io_prio(proc, 2, ulatency.IOPRIO_CLASS_BE)
             end,
  },
  {
    name = "idle",
    param = { ["bfqio.weight"]="1" },
    label = { "daemon.idle", "user.idle" },
    adjust = function(cgroup, proc)
                save_io_prio(proc, 5, ulatency.IOPRIO_CLASS_IDLE)
             end,
  },
  {
    name = "media",
    param = { ["bfqio.weight"]="300" },
    cgroups_name = "grp_${pgrp}",
    label = { "user.media"},
    adjust = function(cgroup, proc)
                save_io_prio(proc, 7, ulatency.IOPRIO_CLASS_RT)
             end,
  },
  {
    name = "group",
    param = { ["bfqio.weight"]="300" },
    cgroups_name = "grp_${pgrp}",
    check = function(proc)
              return proc.pgrp > 0
            end,
    adjust = function(cgroup, proc)
                restore_io_prio(proc)
             end,
  },
  {
    name = "kernel",
    cgroups_name = "",
    check = function(proc)
              return (proc.vm_size == 0)
            end
  },
}

