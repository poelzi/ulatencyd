--[[
    Copyright 2010,2011 ulatencyd developers

    This file is part of ulatencyd.

    License: GNU General Public License 3 or later
]]--

SCHEDULER_MAPPING_DESKTOP = { 
  {
    name = "system_essential",
    cgroups_name = "s_essential",
    param = { ["cpu.shares"]="3048" },
    label = { "system.essential" }
  },
  {
    name = "user",
    cgroups_name = "u_${euid}",
    check = function(proc)
              return ( proc.euid > 999 )
            end,
    param = { ["cpu.shares"]="3048" },
    children = {
      { 
        name = "poison",
        param = { ["cpu.shares"]="10" },
        label = { "user.poison" },
        cgroups_name = "p_${pid}",
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
        name = "poison_session",
        param = { ["cpu.shares"]="600" },
        cgroups_name = "ps_${session}",
        check = function(proc)
                  return ulatency.find_flag(ulatency.list_flags(), {value = proc.session})
                end,
        adjust_new = function(cgroup, proc)
                  local flag = ulatency.find_flag(ulatency.list_flags(), {value = proc.session})
                  cgroup:add_task(proc.pid)
                  cgroup:set_value("memory.soft_limit_in_bytes", flag.threshold)
                  cgroup:commit()
                end
      },
      { 
        name = "bg_high",
        param = { ["cpu.shares"]="1024" },
        label = { "user.bg_high" },
      },
      { 
        name = "media",
        param = { ["cpu.shares"]="2048" },
        label = { "user.media" },
      },
      { 
        name = "ui",
        param = { ["cpu.shares"]="2048" },
        label = { "user.ui" }
      },
      { 
        name = "active",
        param = { ["cpu.shares"]="2048" },
        check = function(proc)
            return proc.is_active
          end
      },
      { 
        name = "idle",
        param = { ["cpu.shares"]="200" },
      },
      { 
        name = "session",
        param = { ["cpu.shares"]="600" },
        cgroups_name = "${session}",
        check = function(proc)
                  return true
                end,
      },
    },
  },
  {
    name = "system",
    cgroups_name = "s_idle",
    label = { "daemon.idle" },
    param = { ["cpu.shares"]="1" },
  },
  {
    name = "system",
    cgroups_name = "s_bg",
    label = { "daemon.bg" },
    param = { ["cpu.shares"]="600" },
  },
  {
    name = "system",
    cgroups_name = "s_daemon",
    check = function(proc)
              -- don't put kernel threads into a cgroup
              return (proc.ppid ~= 0 or proc.pid == 1)
            end,
    param = { ["cpu.shares"]="800" },
  },
}