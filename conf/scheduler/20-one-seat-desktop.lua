--[[
    Copyright 2010,2011 ulatencyd developers

    This file is part of ulatencyd.

    License: GNU General Public License 3 or later
]]--

--[[
    BUGS
    - Needs console-kit
    - If multiple users are logged in, you must quit ulatencyd daemon before shutting the system down. Otherwise
      other users applications may remain frozen and will not get chance to properly shutdown.
      Possible solution:  We need to be informed by session manager.
      Possible workarounds: quit ulatencyd before shutdown, or disable freezer subsystem in cgroups.conf.
    - Processes are not correctly assigned to user sessions (we should check XDG_SESSION_COOKIE variable in a process
      environment, not process UID). If you sudo to root or other user, processeses you run will be considered for
      members of that user session you have sudo to. Processes with EUID 0 are not scheduled by the mappings, so
      if you sudo to root, you only loss some boosts for application executed under sudo. But if you sudo to other user,
      spawn processes may get even frozen!
]]--

SCHEDULER_MAPPING_ONE_SEAT_DESKTOP = {
  info = {
    description = "Advanced scheduler for one seat desktop, processes under inactive sessions "..
    "are scheduled with idle priority or even frozen. You may try to enable the `freezer` cgroup subsystem "..
    "in cgroups.conf. EXPERIMENTAL!"
  }
}

--[[ 
Features:
  - responding to active session change
  - inactive session processes have idle priority, swappiness 100, soft
  memory limit 0 etc.
  - useless processes (flagged with inactive_user.useless, user.media, user.ui,
  user.games, user.idle, daemon.idle) may be frozen, though freezer
  subsystem is disabled by default (see cgroups.conf).
  - boost for starting applications (flagged application.starting), see
  scripts/update-user-apps.sh, scripts/cron.daily/99ulatencyd, generated
  conf/simple.d/applications.conf
  - if starting app is the top most active process at same time, it is
  iosched with real-time policy
  - sets memory.move_charge_at_immigrate = 3 for system essential cgroup
--]]


-- cpu & memory configuration
SCHEDULER_MAPPING_ONE_SEAT_DESKTOP["cpu"] =
{
  {
    name = "rt_tasks",
    cgroups_name = "rt_tasks",
    param = { ["cpu.shares"]="3048", ["?cpu.rt_runtime_us"] = "949500" },
    check = function(proc)
          local rv = proc.vm_size == 0 or proc.received_rt or check_label({"sched.rt"}, proc)
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
    name = "idle_user",
    cgroups_name = "idle_usr_${euid}",
    check = function(proc)
              return ( proc.euid > 999 and proc.euid < 60000 and not ulatency.get_uid_stats(proc.euid) )
            end,
    param = { ["cpu.shares"]="1",  ["?cpu.rt_runtime_us"] = "100" }
  },

  {
    name = "user",
    cgroups_name = "usr_${euid}",
    check = function(proc)
              return ( proc.euid > 999 and proc.euid < 60000 )
            end,
    param = { ["cpu.shares"]="3048",  ["?cpu.rt_runtime_us"] = "100" },
    children = {
      {
        -- top active process, even if poisonous
        name = "active_first",
        cgroups_name = "active",
        param = { ["cpu.shares"]="1500", ["?cpu.rt_runtime_us"] = "1"},
        check = function(proc)
            return proc.is_active and proc.active_pos == 1
          end
      },
      {
        name = "starting",
        cgroups_name = "starting",
        param = { ["cpu.shares"]="1000", ["?cpu.rt_runtime_us"] = "1"},
        label = { "application.starting" },
        check = function(proc)
              local startup = ulatency.match_flag({"startup"})
              if startup then
                for _,p in ipairs(ulatency.list_processes(true)) do
                  p:clear_flag_name("application.starting")
                end
                return false, false
              end
              return true, true
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
        name = "poison",
        param = { ["cpu.shares"]="10" },
        label = { "user.poison" },
        cgroups_name = "psn_${pid}",
      },
      {
        name = "idle",
        param = { ["cpu.shares"]="200"},
        label = { "user.idle", "daemon.idle" },
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
    name = "sys_media",
    param = { ["cpu.shares"]="2500", ["?cpu.rt_runtime_us"] = "1"},
    label = { "daemon.media" },
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
  },
  {
    name = "kernel",
    cgroups_name = "",
    check = function(proc)
              return (proc.vm_size == 0)
            end
  },
  {
    name = "missed",
    cgroups_name = "missed",
    check = function(proc)
              return true
            end,
    adjust = function(cgroup, proc)
              ulatency.log_warning(string.format('scheduler: missed process %d (%s), euid: %d, cmdline: %s',
                    proc.pid, proc.cmdfile or "NONE", proc.euid, proc.cmdline_match or "<no cmdline>"))
            end,
  },
}

SCHEDULER_MAPPING_ONE_SEAT_DESKTOP["memory"] =
{
  {
    name = "system_essential",
    cgroups_name = "sys_essential",
    param = { ["?memory.swappiness"] = "0", ["memory.move_charge_at_immigrate"] = "3" },
    label = { "system.essential" }
  },
  {
    name = "idle_user",
    cgroups_name = "idle_usr_${euid}",
    check = function(proc)
              -- FIXME: proc.euid is probably not always the best choice.
              return ( proc.euid > 999 and proc.euid < 60000 and not ulatency.get_uid_stats(proc.euid) )
            end,
    param = { ["memory.soft_limit_in_bytes"] = "1", ["?memory.swappiness"] = "100", ["?memory.use_hierarchy"] = "1" },
    children = {
      {
        name = "useless",
        label = { "inactive_user.useless", "user.media", "user.ui", "user.games", "user.idle", "daemon.idle" },
      },
      {
        name = "poison",
        label = { "user.poison" },
        cgroups_name = "psn_${pid}",
        adjust_new = function(cgroup, proc)
                  -- we use soft limit, but without limit we can't set the memsw limit
                  local max_rss = math.floor(num_or_percent(ulatency.get_config("memory", "max_rss"),
                                                 Scheduler.meminfo.kb_main_total,
                                                 false) * 1024)
                  local total_limit = math.max(math.floor(num_or_percent(ulatency.get_config("memory", "total_limit"),
                                                   Scheduler.meminfo.kb_main_total + Scheduler.meminfo.kb_swap_total) * 1024),
                                               max_rss)
                  ulatency.log_info("memory container created: ".. cgroup.name .. " max_rss:" .. tostring(max_rss) .. " max_total:" .. tostring(total_limit) .. " soft_limit: 1")
                  cgroup:set_value("memory.limit_in_bytes", max_rss)
                  cgroup:set_value("?memory.memsw.limit_in_bytes", total_limit, max_rss)
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
                  -- we use soft limit, but without limit we can't set the memsw limit
                  local max_rss = math.floor(num_or_percent(ulatency.get_config("memory", "max_rss"),
                                                 Scheduler.meminfo.kb_main_total,
                                                 false) * 1024)
                  local total_limit = math.max(math.floor(num_or_percent(ulatency.get_config("memory", "total_limit"),
                                                   Scheduler.meminfo.kb_main_total + Scheduler.meminfo.kb_swap_total) * 1024),
                                               max_rss)
                  ulatency.log_info("memory container created: ".. cgroup.name .. " max_rss:" .. tostring(max_rss) .. " max_total:" .. tostring(total_limit) .. " soft_limit: 1")
                  cgroup:set_value("memory.limit_in_bytes", max_rss)
                  cgroup:set_value("?memory.memsw.limit_in_bytes", total_limit, max_rss)
                end
      },
    },
  },


  {
    name = "user",
    cgroups_name = "usr_${euid}",
    check = function(proc)
              return ( proc.euid > 999 and proc.euid < 60000 )
            end,
    children = {
      {
      {
        name = "bg_high",
        param = { ["?memory.swappiness"] = "20" },
        label = { "user.bg_high" },
      },
      {
        name = "ui",
        param = { ["?memory.swappiness"] = "10" },
        label = { "user.ui" }
      },
      {
        name = "active",
        param = { ["?memory.swappiness"] = "20" },
        check = function(proc)
                if not proc.is_active then return false end
                for j, flag in pairs(ulatency.list_flags()) do
                  if flag.name == "pressure" or flag.name == "emergency" then
                  return proc.active_pos == 1
                end
              end
              return true
            end
      },
      {
        name = "media",
        param = { ["?memory.swappiness"] = "40" },
        label = { "user.media" },
      },
        name = "poison",
        label = { "user.poison" },
        cgroups_name = "psn_${pid}",
        param = { ["?memory.swappiness"] = "100" },
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
                  cgroup:set_value("?memory.memsw.limit_in_bytes", total_limit, max_rss)
                end
      },
      {
        name = "poison_group",
        cgroups_name = "pgr_${pgrp}",
        param = { ["?memory.swappiness"] = "100" },
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
                  cgroup:set_value("?memory.memsw.limit_in_bytes", total_limit, max_rss)
                end
      },
      {
        name = "idle",
        param = { ["?memory.swappiness"] = "100" },
        label = { "user.idle", "daemon.idle" },
      },
      {
        name = "group_pressure",
        sysflags = {"pressure", "emergency"},
        param = {["?memory.swappiness"] = "100" },
        cgroups_name = "default_pressure",
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
    name = "sys_media",
    param = { ["?memory.swappiness"] = "40" },
    label = { "daemon.media" },
  },
  {
    name = "system",
    cgroups_name = "sys_daemon",
    check = function(proc)
              -- don't put kernel threads into a cgroup
              return (proc.pgrp > 0)
            end,
    param = { ["?memory.swappiness"] = "80" },
  },
  {
    name = "kernel",
    cgroups_name = "",
    check = function(proc)
              return (proc.vm_size == 0)
            end
  },
  {
    name = "missed",
    cgroups_name = "missed",
    check = function(proc)
              return true
            end,
    adjust = function(cgroup, proc)
              ulatency.log_warning(string.format('scheduler: missed process %d (%s), euid: %d, cmdline: %s',
                    proc.pid, proc.cmdfile or "NONE", proc.euid, proc.cmdline_match or "<no cmdline>"))
            end,
  },
}


-- io configuration. blkio does not support hirarchies
SCHEDULER_MAPPING_ONE_SEAT_DESKTOP["blkio"] =
{
  --! catch user.idle labeled processes, they should have lowest priority
  {
    name = "idle",
    param = { ["blkio.weight"]="10" },
    label = { "daemon.idle", "user.idle" },
    adjust = function(cgroup, proc)
                save_io_prio(proc, 7, ulatency.IOPRIO_CLASS_IDLE)
             end,
  },

  {
    name = "idle_user",
    cgroups_name = "idle_usr_${euid}",
    check = function(proc)
                return ( proc.euid > 999 and proc.euid < 60000 and not ulatency.get_uid_stats(proc.euid) )
              end,
    param = { ["blkio.weight"]="10" },
    adjust = function(cgroup, proc)
                save_io_prio(proc, 7, ulatency.IOPRIO_CLASS_IDLE)
              end
  },
  {
    name = "media",
    param = { ["blkio.weight"]="300" },
    cgroups_name = "grp_${pgrp}",
    label = { "user.media"},
    adjust = function(cgroup, proc)
                save_io_prio(proc, 1, ulatency.IOPRIO_CLASS_RT)
             end,
  },
  {
    name = "ui",
    label = { "user.ui" },
    adjust = function(cgroup, proc)
                save_io_prio(proc, 3, ulatency.IOPRIO_CLASS_RT)
             end,
  },
  {
    name = "active",
    cgroups_name = "usr_${euid}_active",
    param = { ["blkio.weight"]="1000" },
    check = function(proc)
                return proc.active_pos == 1
              end,
    adjust = function(cgroup, proc)
                if ulatency.match_flag({"application.starting"}, proc) then
                  ulatency.log_info(
                    string.format("Boosting starting active application to Real-Time IO policy: %s [%d]",
                      (proc.cmdfile or "(no cmdline)"), proc.pid
                    )
                  )
                  save_io_prio(proc, 7, ulatency.IOPRIO_CLASS_RT)
                else
                  save_io_prio(proc, 0, ulatency.IOPRIO_CLASS_BE)
                end
              end,
  },
  {
    name = "starting-application",
    cgroups_name = "starting-user-application",
    param = { ["blkio.weight"]="500" },
    label = { "application.starting" },
    checks = {
          function(proc)
            return ( proc.euid > 999 and proc.euid < 60000 )
          end,
          function(proc)
            local startup = ulatency.match_flag({"startup"})
            if startup then
              for _,p in ipairs(ulatency.list_processes(true)) do
                p:clear_flag_name("application.starting")
              end
              return false, false
            end
            return true, true
          end,
    },
    adjust = function(cgroup, proc)
                --if proc.is_valid and proc.changed then
                  ulatency.log_info(
                    string.format("Boosting starting application IO priority: %s [%d]",
                      (proc.cmdfile or "(no cmdline)"), proc.pid
                    )
                  )
                --end
                save_io_prio(proc, 1, ulatency.IOPRIO_CLASS_BE)

                --[[ lower others?
                for _, task in cgroup:get_tasks() do
                  local parent = task:get_parent()
                  if parent.pid ~= proc.pid and task.pgrp ~= proc.pgrp
                    save_io_prio(t, 7, ulatency.IOPRIO_CLASS_BE)
                  end
                end
                --]]
             end,
  },
  {
    name = "sys_media",
    param = { ["blkio.weight"]="300" },
    label = { "daemon.media"},
    adjust = function(cgroup, proc)
                save_io_prio(proc, 1, ulatency.IOPRIO_CLASS_RT)
             end,
  },
  {
    name = "system",
    cgroups_name = "sys_bg",
    label = { "daemon.bg" },
    param = { ["blkio.weight"]="15" },
    adjust = function(cgroup, proc)
                save_io_prio(proc, 6, ulatency.IOPRIO_CLASS_IDLE)
             end,
  },
  {
    name = "poison",
    label = { "user.poison", "user.poison.group" },
    cgroups_name = "psn_${pgrp}",
    param = { ["blkio.weight"]="10" },
    adjust = function(cgroup, proc)
                save_io_prio(proc, 0, ulatency.IOPRIO_CLASS_IDLE)
             end,
  },

  --! active user other
  {
    name = "group",
    param = { ["blkio.weight"]="300" },
    cgroups_name = "usr_grp_${pgrp}",
    check = function(proc)
                return proc.euid > 999 and proc.euid < 60000
              end,
    adjust = function(cgroup, proc)
                restore_io_prio(proc)
              end,
  },


  --! system other
  {
    name = "system",
    cgroups_name = "sys_grp_${pgrp}",
    check = function(proc)
                -- don't put kernel threads into a cgroup
                return (proc.pgrp > 0)
              end,
    param = { ["blkio.weight"]="10" },
    --adjust = function(cgroup, proc)
    --            save_io_prio(proc, 7, ulatency.IOPRIO_CLASS_BE)
    --         end,
  },

  {
    name = "kernel",
    cgroups_name = "",
    check = function(proc)
                return (proc.vm_size == 0)
              end
  },
  {
    name = "missed",
    cgroups_name = "missed",
    check = function(proc)
                return true
              end,
    adjust = function(cgroup, proc)
                ulatency.log_warning(string.format('scheduler: missed process %d (%s), euid: %d, cmdline: %s',
                      proc.pid, proc.cmdfile, proc.euid, proc.cmdline_match or "<no cmdline>"))
              end,
  },
}

-- TODO: freeze and thaw only once for whole shceduler run
SCHEDULER_MAPPING_ONE_SEAT_DESKTOP["freezer"] =
{
  {
    name = "user",
    cgroups_name = "usr_${euid}",
    check = function(proc)
                return ( proc.euid > 999 and proc.euid < 60000 )
              end,
    param = { ["freezer.state"] = "THAWED" },
    children = {
      {
        name = "inactive_user.useless",
        label = { "inactive_user.useless", "user.media", "user.ui", "user.games", "user.idle", "daemon.idle" },
        adjust = function(cgroup, proc)
                if ulatency.get_uid_stats(proc.euid) or ulatency.match_flag({"quit","suspend"}) then
                  if cgroup:get_value("freezer.state") == 'FROZEN' then
                    Scheduler:register_after_hook('thaw group ' .. cgroup.name, function()
                        ulatency.log_info('thawing group ' .. cgroup.name)
                      end
                    )
                  end
                  cgroup:set_value("freezer.state", 'THAWED')
                else
                  Scheduler:register_after_hook('freeze group ' .. cgroup.name, function()
                      if cgroup:get_value("freezer.state") == 'THAWED' then
                        ulatency.log_info('freezing group ' .. cgroup.name)
                        cgroup:set_value("freezer.state", 'FROZEN')
                        cgroup:commit()
                      end
                    end
                  )
                end
                return false -- do not run again
            end,
      },
    },
  },
  {
    name = "other",
    cgroups_name = "",
    check = function(proc)
                return true
              end,
  }
}
