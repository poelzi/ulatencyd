--[[
    Copyright 2010,2011 ulatencyd developers

    This file is part of ulatencyd.

    License: GNU General Public License 3 or later
]]--

SCHEDULER_MAPPING_SINGLE_TASK = {
  info = {
    description = "a good default desktop configuration",
    hidden = true
  },
}


-- cpu & memory configuration
SCHEDULER_MAPPING_SINGLE_TASK["cpu"] =
{
  {
    name = "rt_tasks",
    cgroups_name = "rt_tasks",
    param = { ["cpu.shares"]="3048", ["?cpu.rt_runtime_us"] = "949500" },
    check = function(proc)
          local rv = proc.received_rt or check_label({"sched.rt"}, proc) or proc.vm_size == 0
          return rv
        end,
  },
  {
    name = "system_essential",
    cgroups_name = "sys_essential",
    param = { ["cpu.shares"]="100" },
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
        name = "task",
        param = { ["cpu.shares"]="100", ["?cpu.rt_runtime_us"] = "1"},
        label = { "user.single_task" },
        check = function(proc)
            return proc.active_pos == 1
          end
      },
      {
        name = "active",
        param = { ["cpu.shares"]="30", ["?cpu.rt_runtime_us"] = "1"},
        check = function(proc)
            return proc.active_pos == 1
          end
      },
      {
        name = "group",
        param = { ["cpu.shares"]="5", ["?cpu.rt_runtime_us"] = "1"},
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
    cgroups_name = "sys",
    check = function(proc)
              return ( proc.euid > 999 )
            end,
    param = { ["cpu.shares"]="100",  ["?cpu.rt_runtime_us"] = "100" },
    children = {
      {
        name = "system_group",
        cgroups_name = "pgr_${pgrp}",
        check = function(proc)
                  -- don't put kernel threads into a cgroup
                  return (proc.ppid ~= 0 or proc.pid == 1)
                end,
        param = { ["cpu.shares"]="30",
                  ["?cpu.rt_runtime_us"] = "1"},
      },
    }
  },
}

SCHEDULER_MAPPING_SINGLE_TASK["memory"] =
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
        name = "task",
        param = { ["?memory.swappiness"] = "20" },
        label = { "user.single_task" },
        adjust_new = function(cgroup, proc)
            local max_rss = Scheduler.meminfo.kb_main_total * 0.90 * 1024
            cgroup:set_value("memory.limit_in_bytes", max_rss)
        end

      },
      {
        name = "group",
        param = {["?memory.swappiness"] = "100" },
        cgroups_name = "default",
        check = function(proc)
                  return true
                end,
        adjust_new = function(cgroup, proc)
            local max_rss = Scheduler.meminfo.kb_main_total * 0.10 * 1024
            cgroup:set_value("memory.limit_in_bytes", max_rss)
        end
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
    name = "system",
    cgroups_name = "sys_daemon",
    check = function(proc)
              -- don't put kernel threads into a cgroup
              return (proc.ppid ~= 0 or proc.pid == 1)
            end,
    param = { ["?memory.swappiness"] = "70" },
  },
  { 
    name = "kernel",
    cgroups_name = "",
    check = function(proc)
              return (proc.vm_size == 0)
            end
  },

}


-- io configuration. blkio does not support hirarchies
SCHEDULER_MAPPING_SINGLE_TASK["blkio"] =
{
  { 
    name = "task",
    cgroups_name = "usr_${euid}_single_task",
    param = { ["blkio.weight"]="1000" },
    label = { "user.single_task" },
  },
  { 
    name = "group",
    param = { ["blkio.weight"]="1" },
    cgroups_name = "grp_${pgrp}",
    check = function(proc)
              return proc.pgrp > 0
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

