The default scheduler (`rules/scheduler.lua`) uses a decision tree.
You can have different configurations that are set in the `ulatencyd.conf`, but only one can be active at any time.

The scheduler finds it's decision by traveling down the rules top to bottom and checking each entry. The first rule that
matches will be used. If the rule contains children rules, these are checked in the same manner.

Lets look at the [default config](https://github.com/poelzi/ulatencyd/blob/master/rules/scheduler_desktop.lua):
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
            ...

`cm` is the cgroups toplevel tree configured in `cgroups.conf`. If no cgroups subsystem is available from this group, the tree is skipped. The scheduler will start looking at `system_essential` if it matches, it will use it, if not, `user` is checked and so on. 

# Entries of a map
Lets look at at one entry:
    {
      name = "sometest",
      cgroups_name = "test_${euid}",
      label = { "testflag" }
      check = function(proc)
                return ( proc.euid == 1020 )
              end,
      param = { ["cpu.shares"]="1001" },
    }

* `name` is a human readable entry, not necessary but good to have. 
* `cgroups_name` is the name to use for creating the subdirectory in cgroups. If it is a string, values written with
  `${NAME}` will be substituted by the values of the process object. If it is a function, it gets the process as first
  argument and must return a string.
* `label` is a table of strings that are checked against the flags of the process. If any flags name matches any entry
  of the label list, the rule matches. If label and a check function exists, the check function is only called when the
  label matches.
* `check(proc)` is a function that will be called with the process. If it returns `true`, the rule matches.
* `param` are the default parameters that will be used for this cgroup. They represent the cgroups subsystem values set
  for the subsystems mounted. `cm` for example mounts the cpu, cpuset and memory subsystem. `cpu.shares` represent the
  amount of of cpu power this group will get. For values see the cgroups documentation below.
* `adjust(cgroup, proc)` is a function that is called with the cgroup and proc object. It can adjust the cgroup parameter 
  for better fitting. Important: this function is called everytime a process runs through.
* `adjust_new(cgroup, proc)` this function is only called once a new cgroup is created. When a cgroup does not have any 
  processes anymore, it is deleted and the adjust_new function will be called again.

# If this does not fit
If the default mapping does not suite you, write another. It would be great if you share it by adding it as a ticket.

If this rule based approach does not fit you, you can replace it with something different by editing `rules/scheduler.lua`

# cgroups documentation
* [cpu scheduler](http://www.kernel.org/doc/Documentation/scheduler/sched-design-CFS.txt)
* [cgroups docs](http://www.kernel.org/doc/Documentation/cgroups/)
* [blockio docs](http://www.mjmwired.net/kernel/Documentation/cgroups/blkio-controller.txt)
