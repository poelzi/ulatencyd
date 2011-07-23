--[[
    Copyright 2010,2011 ulatencyd developers

    This file is part of ulatencyd.

    License: GNU General Public License 3 or later
]]--

SCHEDULER_MAPPING_VIDEO_PLAYBACK = {
  info = {
    description = "a scheduler for video playback. EXPERIMENTAL",
    hidden = true
  }
}


-- cpu & memory configuration
SCHEDULER_MAPPING_VIDEO_PLAYBACK["cpu"] =
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
        name = "media",
        param = { ["cpu.shares"]="3000", ["?cpu.rt_runtime_us"] = "1"},
        label = { "user.media" },
      },
      { 
        name = "bg_high",
        param = { ["cpu.shares"]="500",  ["?cpu.rt_runtime_us"] = "1"},
        label = { "user.bg_high" },
      },
      { 
        name = "ui",
        param = { ["cpu.shares"]="1000", ["?cpu.rt_runtime_us"] = "1"},
        label = { "user.ui" }
      },
      { 
        name = "idle",
        param = { ["cpu.shares"]="1"},
        label = { "user.idle" },
      },
      { 
        name = "group",
        param = { ["cpu.shares"]="50", ["?cpu.rt_runtime_us"] = "1"},
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
              return (proc.ppid ~= 0 or proc.pid == 1)
            end,
    param = { ["cpu.shares"]="800",
              ["?cpu.rt_runtime_us"] = "1"},
  }
}

if ulatency.smp_num_cpus > 1 then
  local all_cpus = "0-"..tostring((ulatency.smp_num_cpus-1 or 0))
  local rest_cpu = "0"
  local media_label = { "user.media" }
  -- use special cases for low number of processors
  if ulatency.smp_num_cpus == 2 then
    essential_cpu = "0"
    other_cpu = "0"
    media_cpu = "1"
    media_exc = "1"
  else
    other_cpu = "0"
    media_label = { "user.media", "system.essential"}

    media_cpu = "1-"..tostring((ulatency.smp_num_cpus-1))
    media_exc = "1"
  end

  SCHEDULER_MAPPING_VIDEO_PLAYBACK["cpuset"] =
  {
      { 
        name = "media",
        param = { ["?cpuset.mems"] = "0",
                  ["?cpuset.cpus"] = media_cpu,
                  ["?cpuset.cpu_exclusive"] = media_exc,},
        label = media_label,
      },
      { 
        name = "essential",
        param = { ["?cpuset.mems"] = "0",
                  ["?cpuset.cpus"] = essential_cpu,
                  ["?cpuset.cpu_exclusive"] = essential_exc,},
        label = { "system.essential" },
      },
      { 
        name = "other",
        param = { ["?cpuset.mems"] = "0",
                  ["?cpuset.cpus"] = other_cpu,
                  ["?cpuset.cpu_exclusive"] = other_exc,},
        check = function(proc) return true end,
      },
  }
end

SCHEDULER_MAPPING_VIDEO_PLAYBACK["memory"] = merge_config(SCHEDULER_MAPPING_DESKTOP["memory"], 
  {
   replace = 
    {
      { 
        name = "media",
        param = { ["?memory.swappiness"] = "0" },
        label = { "user.media" },
      },
    }

 }
)


-- io configuration. blkio does not support hirarchies
SCHEDULER_MAPPING_VIDEO_PLAYBACK["blkio"] = merge_config(SCHEDULER_MAPPING_DESKTOP["blkio"], 
  {
   replace = 
    {
      {
      name = "media",
      param = { ["blkio.weight"]="1000" },
      cgroups_name = "grp_${pgrp}",
      label = { "user.media"},
      adjust = function(cgroup, proc)
            save_io_prio(proc, 7, ulatency.IOPRIO_CLASS_RT)
           end,
      },
    },
  }
)

SCHEDULER_MAPPING_VIDEO_PLAYBACK["bfqio"] = merge_config(SCHEDULER_MAPPING_DESKTOP["bfqio"], 
  {
   replace = 
    {
      {
      name = "media",
      param = { ["bfqio.weight"]="1000" },
      cgroups_name = "grp_${pgrp}",
      label = { "user.media"},
      adjust = function(cgroup, proc)
            save_io_prio(proc, 7, ulatency.IOPRIO_CLASS_RT)
           end,
      },
    },
  }
)
