--[[
    Copyright 2010,2011 ulatencyd developers

    This file is part of ulatencyd.

    License: GNU General Public License 3 or later
]]--

SCHEDULER_MAPPING_CLEANUP = {
  info = {
    description =
    "This configuration is responsible for cleaning up before ulatencyd exists, "..
    "if active configuration has not performed clean up itself (didn't remove system cleanup flag). "..
    "In that case scheduler performs additional full run with this configuration just before ulatencyd exists.",
    hidden = true
  }
}

SCHEDULER_MAPPING_CLEANUP["cpu"] =
{
  {
    name = "cleanup",
    cgroups_name = "",
    check = function(proc)
          return true
        end
  }
}

SCHEDULER_MAPPING_CLEANUP["memory"] =
{
  {
    name = "cleanup",
    cgroups_name = "",
    check = function(proc)
          return true
        end
  }
}

SCHEDULER_MAPPING_CLEANUP["blkio"] =
{
  {
    name = "cleanup",
    cgroups_name = "",
    check = function(proc)
          return true
        end,
    adjust = function(cgroup, proc)
          restore_io_prio(proc)
        end
  }
}

SCHEDULER_MAPPING_CLEANUP["bfqio"] =
{
  {
    name = "cleanup",
    cgroups_name = "",
    check = function(proc)
          return true
        end,
    adjust = function(cgroup, proc)
          restore_io_prio(proc)
        end
  }
}

SCHEDULER_MAPPING_CLEANUP["cpuset"] =
{
  {
    name = "cleanup",
    cgroups_name = "",
    check = function(proc)
          return true
        end
  }
}

SCHEDULER_MAPPING_CLEANUP["freezer"] =
{
  {
    name = "cleanup",
    cgroups_name = "",
    check = function(proc)
          return true
        end
  }
}
