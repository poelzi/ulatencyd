--[[
    Copyright 2010,2011 ulatencyd developers

    This file is part of ulatencyd.

    License: GNU General Public License 3 or later
]]--

SCHEDULER_MAPPING_GAME = {
  info = {
    description = "scheduler for games",
  },
}


-- cpu & memory configuration
SCHEDULER_MAPPING_GAME["cpu"] =
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
        name = "ui",
        param = { ["cpu.shares"]="200", ["?cpu.rt_runtime_us"] = "1"},
        label = { "user.ui" }
      },
      {
        name = "media",
        param = { ["cpu.shares"]="1000", ["?cpu.rt_runtime_us"] = "1"},
        label = { "user.media" },
      },
      {
        name = "game",
        param = { ["cpu.shares"]="3048", ["?cpu.rt_runtime_us"] = "1"},
        check = function(proc)
            return proc.active_pos == 1 or check_label({ "cmd.config.game", "user.game" }, proc)
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
    param = { ["cpu.shares"]="100",  ["?cpu.rt_runtime_us"] = "100" },
    check = function(proc)
              return true
            end,
    children = {
      {
        name = "system_group",
        cgroups_name = "pgr_${pgrp}",
        param = { ["cpu.shares"]="30",
                  ["?cpu.rt_runtime_us"] = "1"},
        check = function(proc)
                  return true
                end,
      },
    }
  },
}

SCHEDULER_MAPPING_GAME["memory"] =
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
        name = "game",
        param = { ["?memory.swappiness"] = "20" },
        label = { "user.game", "cmd.config.single_task" },
        adjust_new = function(cgroup, proc)
            local max_rss = Scheduler.meminfo.kb_main_total * 0.80 * 1024
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
SCHEDULER_MAPPING_GAME["blkio"] =
{
  {
    name = "task",
    cgroups_name = "usr_${euid}_game",
    param = { ["blkio.weight"]="1000" },
    label = { "user.game", "cmd.config.game"},
  },
  {
    name = "group",
    param = { ["blkio.weight"]="100" },
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

SCHEDULER_MAPPING_GAME["bfqio"] =
{
  {
    name = "task",
    cgroups_name = "usr_${euid}_game",
    param = { ["bfqio.weight"]="1000" },
    label = { "user.game", "cmd.config.game"},
  },
  {
    name = "group",
    param = { ["bfqio.weight"]="1" },
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

