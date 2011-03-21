Rules are written in the [Lua](http://www.lua.org/) programming language. You can find good Tutorials and the Documentation
on the [Lua website](http://www.lua.org/docs.html). Lua is a small, very fast functional programming language that fits perfect to do this job.

## Two types of invocation 
Rules contain usually one or more Filters. These filters are called on a process which it can manipulate.
Normally these manipulations tagging the the process with a flag that is later used by the scheduler.

The second method you have is registering a timeout function that is called independent from the iteration interval.
This is useful for example to check the system for specific conditions to apply. The `rules/protector.lua` script for example uses this for detecting memory pressure.

### Filters:
    MyExample = {
      name = "MyExample",
      re_basename = "my_windowmanage",
      check = function(self, proc)
        local flag = ulatency.new_flag{name="user.ui"}
        proc:add_flag(flag)
    
        return ulatency.filter_rv(ulatency.FILTER_STOP)
      end
    }
    ulatency.register_filter(KdeUI)
This is an simple example filter. Lets take a look what it does:
Each filter is a lua table, which is created by `{}`

    MyExample = {

just creates a new variable with name `MyExample`.
The `name` is not required, but strongly suggested.

    re_basename = "my_windowmanage",

This is a prefilter for the check function. If any prefilter exist, they must apply to the process for the check function to get called. If you can't create a regular expression to match only on the processes you want, you can still do more filtering on the actual check function. These prefilters exist to reduce the calls into lua, as they are compiled regular expressions that are executed very fast in the C core.
If no prefilter exist, the check function is always called.

    check = function(self, proc)

This is the real heart of the filter. It gets passed an process instance which it should analyze and manipulate with it's decisions.

The most common case of maipulation is the adding of flags.
    local flag = ulatency.new_flag{name="user.ui"}
    proc:add_flag(flag)

You can create a new flag with `ulatency.new_flag{parameter=value, parameter2=value2,...}`. This instances can be added
to as many processes you like. As they are references, changing a value of a flag will change them on all processes.

The return value of the check filter is used to notify the core how the filter is used on future runs on a per process bases.
    return ulatency.filter_rv(ulatency.FILTER_STOP)
This means that this filter will never be run again on **this process**. If you mark a process with some flags that will never change, that will never time out, you don't need to run the filter again, ever. If you don't do this, the filter
gets executed every iteration causing to get more and more flags if you don't delete them first.
The return value is composed of those values:
`ulatency.filter_rv(FLAGS, TIMEOUT)`
Flags can be 

* ulatency.FILTER_STOP
  Will stop the filter on this process
* ulatency.FILTER_SKIP_CHILD
  Will skip all child processes of the current process

Timeout is a integer in seconds, that the filter will not be run again. If you want for example skip this filter for the 
next 5 minutes on this process you can return:

`ulatency.filter_rv(0, 5*60)`

If you simply return `0`, the filter is executed on the next iteration again.


## Full Filter definition
    MyFilter = {
      name = "MyFilter",           -- human readable name used in reporting
      re_basename = <PERL_REGEXP>, -- perl regular expression to match against the executable name
      re_cmdline = <PERL_REGEXP>   -- perl regular expression to match against the command line used
      min_percent = <decimal>      -- min percent of load the system must have 
      precheck = function(self)
                -- executed before any process. if exits must return
                -- true for filter to get run
      end
    
      check = function(self, proc)
                -- check one process. all processes are checked in process tree order form the top (init)
                -- descenting all children
      end
    
      postcheck = function(self)
                -- run after all processes are processed. You can make final manipulations to processes here.
      end
      exit = function(self, proc)
                -- only called when the process is removed from the process list. most functions calls on the
                -- process will fail. Useful for cleanup data in filters
      end
    }
`

## Full Flag definition

    flag = ulatency.new_flag{
                   name=[string],           -- name of the flag. the convention is to use a hierarchy seperated by .
                   inherit=[boolean],       -- will apply to all children
                   timeout=[unix timestemp] -- timeout when the flag will disappear. create it with 
                                            -- ulatency.get_time(seconds)
                   reason=[string],         -- why the flag was set. this makes most sense with emergency flags, but
                                            -- can be set to any string value
                   priority=[integer],      -- custom data: priority
                   value=[integer]          -- custom data: value
                   threshold=[integer]      -- custom data: threshold
    }

Prefilters:

    min_percent = <decimal>                   - min percent of of cpu utilization. means load/number_of_cores
    precheck()

The pre filters are checked first, and if they exist and apply, filter is run. If no pre filters exist, the filter is run.

Per process prefilters:
  re_basename = <perl regular expression>   - Regular expression must match the basename of process
  re_cmdline = <perl regular expression>    - Must match the command line

**Warning**: 
The prefilters can't currently be changed after registering the filter.
basename is limited to 15 chars.

Prefilters reduce the amount of filter calling by using fast c checks before the
check function is called. 

The check function returns an integer that contains informs the core about two 
things. An timeout value of 16 bits in seconds when the filter should be run again,
and flags about the transversel.

  FILTER_STOP         -- stops the filter on this process, so it is never run again
  FILTER_SKIP_CHILD   -- skips all child process of the current process

FILTER_STOP is very important. If you have a static filter that marks the process
with a flag and you will never change that label on this process, you simple return
FILTER_STOP. The flag will stay on the process for it's lifetime.

the return value is calculated with:
ulatency.filter_rv(ulatency.FILTER_A [+ulatency.FILTER_B ...] , [timeout])

**warning**: as lua does not have OR on integer values and the flags are binary
flags, you have to make sure not to generate invalid flags if you calculate them
through addition.

## Important to know:

Process objects are shared between all parts of ulatencyd. If you save a reference you do
not save the data, but only a reference to it. Accessing values will always be
the most recent version of it. If you want create a history of data, you have
to store them as copies. If you save references they may be to a dead process, but
still there. To prevent memory leaks you should check them periodically if they are
still valid. You can check if the process of your reference is still alive with
`proc.is_valid`.

Best practice is to store your data attached to the process, so it gets collected
when the process dies. Use `proc.data` for a table shared between all lua scripts.
You should use `proc.data[SOMEUNIQUESTRING]` to prevent clashes between rules.

## !!! Don't do's !!!

Try not to fork or execute external programs from rules. This is especially
important when you try to detect something like a fork bomb or extreme load...
If you store data, cleanup your memory. You can easliy register a cleanup
timeout function for that.