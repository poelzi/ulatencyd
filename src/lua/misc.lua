--[[
    Copyright 2010,2011 ulatencyd developers

    This file is part of ulatencyd.

    ulatencyd is free software: you can redistribute it and/or modify it under 
    the terms of the GNU General Public License as published by the 
    Free Software Foundation, either version 3 of the License, 
    or (at your option) any later version.

    ulatencyd is distributed in the hope that it will be useful, 
    but WITHOUT ANY WARRANTY; without even the implied warranty of 
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
    See the GNU General Public License for more details.

    You should have received a copy of the GNU General Public License 
    along with ulatencyd. If not, see http://www.gnu.org/licenses/.
]]--

-------------------------------------------------------------------------------
--! @file
--! @ingroup lua_lua_HELPERS
--! @brief miscellaneous functions
-------------------------------------------------------------------------------


posix = require("posix")

--! @addtogroup lua_HELPERS
--! @{


--! @brief Recursively creates a directory.
--! @param path Full path of the new directory.
--! @param quiet If true, do not log errors
--! @return boolean
--! @retval 0 if the directory was successfully created or already exists
--! @retval nil, errstr, errno if creation of some directory along the `path` failed.
function mkdirp(path, quiet)
  if not posix.access(path, "f") then
    local parts = path:split("/")
    for i,v in ipairs(parts) do
      name = "/" .. table.concat(parts, "/", 1, i)

      if not posix.access(name, "f") then -- this fail if `name`
                  -- (e.g /sys/fs/cgroup/cpu) is a symlink not created by root
        local ok, errstr, errno = posix.mkdir(name)
        if not ok then
          if not quiet then
            cg_log("mkdirp(%s): Can't create directory: %s", path, errstr)
          end
          return nil, errstr, errno
        end
      end

    end
  end
  return 0
end

do
  -- seen move tasks errors that should be reported only once
  -- { ['cpu.rt_task'] = true } failed moving of real-time processes on non
  --                            CONFIG_RT_GROUP_SCHED kernel
  local reported_move_task_errors = {}

  --! @brief Log error after writing to sysfs failed: decides whether the error
  --! should be logged, the log level and composes the error message.
  --! @param filepath The file full path
  --! @param value A value that trigger the error
  --! @param err Textual representation of the error
  --! @param err_code The error code (a number)
  function sysfs_write_error(filepath, value, err, err_code)
    -- is writing to file inside CGROUP_ROOT ?
    local cgr_name, cgr, subsys, file
    local s,e = string.find(filepath, CGROUP_ROOT, 1, true)
    if s == 1 then
      -- yes, so this is error while writing to a cgroup subsystem
      local fields = string.split(string.sub(filepath, e+1), '/')
      if #fields >= 2 then
        subsys = fields[1]
        file = fields[#fields]
        cgr_name = #fields >= 3 and
                   table.concat(fields, '/', 2, #fields-1) or ""
        cgr = CGroup.get_group(subsys ..'/'.. cgr_name)
      end
    end

    ----------------------------------------------------------------------------
    -- Begin handling error: Task could not be added to a cgroup
    ----------------------------------------------------------------------------

    if cgr and file == "tasks" then
      -- ignore errors "no such process"
      if err_code == 3 then
        return
      end
      -- try to get both U_PROC and U_TASK instance as we do not know if
      -- the moving process is a thread (task) or thread leader (process)
      local proc = ulatency.get_pid(value)
      local task = ulatency.get_tid(value)
      -- skip if the task should be reported only once and
      -- this already happened
      if task and task.data.do_not_report_move_errors and
                  task.data.do_not_report_move_errors[cgr.tree]
      then
        return
      end

      --- Special cases

      -- additional info to be logged
      local props = {} -- additional task/proc properties
      local info = {}  -- texts to be displayed after the message
      local log_level = ulatency.LOG_LEVEL_WARNING

      -- if kernel process failed to be moved and was never moved before
      -- in any cgroup subsystem then skip future scheduling
      if task and task.euid == 0 and task.egid == 0 and
            task.vm_size == 0
      then
        if not task.data.do_not_report_move_errors then
          task.data.do_not_report_move_errors = {}
        end
        props[#props+1] = "KERNEL PROCESS"
        if proc then
          -- disable move errors reporting of such subsystems where the
          -- process is in root cgroup.
          local cgroups = {}
          local in_root_cgroups = true
          for _, subsys in ipairs(ulatency.get_cgroup_subsystems()) do
            if ulatency.has_cgroup_subsystem(subsys) then
              local cgr_path = proc:get_cgroup(subsys)
              if cgr_path and cgr_path ~= "/" then
                cgroups[#cgroups+1] = subsys..":"..cgr_path
                in_root_cgroups = false
              elseif ulatency.tree_loaded(subsys) then
                task.data.do_not_report_move_errors[subsys] = true
              end
            end
          end
          if #cgroups > 1 then
            props[#props+1] = "cgroups / in every subsys except "..
                              table.concat(cgroups,",")
          else
            props[#props+1] = "cgroups: / in every subsys"
          end
          -- if process is in root cgroup of every subsystem then block it
          -- from scheduler, this is expected as some kernel processes are
          -- not movable, but I could not find the pattern, therefore they are
          -- detected here
          if in_root_cgroups then
            proc:set_block_scheduler(1, "the pid is unmovable kernel task")
            info[#info+1] = "This is probably kernel unmovable task"..
                  " and will not be scheduled again."
            log_level = ulatency.LOG_LEVEL_SCHED
          -- otherwise just report
          else
            info[#info+1] = "This may be kernel unmovable task, but has"..
                  " already been moved from root cgroup in some subsystem!"
            info[#info+1] = "Therefore it won't be blocked from scheduling"..
                  " but this error won't be printed again."
            --proc:set_block_scheduler(0)
          end
        end -- proc

      -- error while moving rt task in cpu subsystem
      -- on kernel without CONFIG_RT_GROUP_SCHED
      elseif cgr.tree == "cpu" and err_code == 22 and
         posix.access(cgr:path("cpu.rt_runtime_us")) ~= 0
      then
        if task and ( task.sched == ulatency.SCHED_RR or
                      task.sched == ulatency.SCHED_FIFO )
        then
          -- report only once
          if reported_move_task_errors['cpu.rt_task'] then
            return
          end
          reported_move_task_errors['cpu.rt_task'] = true
          props[#props+1] = "RT sched"
          info[#info+1] =
                "\nYour kernel is probably compiled without"..
                " CONFIG_RT_GROUP_SCHED; consider recompiling; no future"..
                " error of this type will be logged."
        end

      -- cpuset: include cpuset.cpus and cpuset.mems value to the log
      elseif cgr.tree == "cpuset" then
        local files = {}
        for _,file in ipairs{"cpuset.cpus", "cpuset.mems"} do
          local fh = io.open(cgr:path(file))
          if fh then
            files[file] = fh:read("*a"):rtrim()
            props[#props+1] = file.."="..files[file]
            fh:close()
          end
        end
      end

      -- print error
      if proc and ulatency.LOG_LEVEL >= log_level then
        ulatency.log(log_level,
              "Process (PID:%s, ppid:%s, euid:%s, egid:%s, cmd:%s, "..
              "cmdfile:%s, exe:%s, cgr:%s%s) couldn't be moved to %s (%d:%s)%s",
              tostring(value), proc.ppid or "?",
              proc.euid or "?", proc.egid or "?",
              proc.cmd or "?", proc.cmdfile or "?", proc.exe or '?',
              proc:get_cgroup(subsys) or "?",
              #props > 0 and ", "..table.concat(props,", ") or "",
              tostring(cgr), err_code, err,
              #info > 0 and " "..table.concat(info," ") or "" )
      elseif ulatency.LOG_LEVEL >= log_level then
        ulatency.log(log_level,
              "Task (TID:%s, ppid:%s, euid:%s, egid:%s, cmd:%s%s)"..
              " couldn't be moved to %s (%d:%s)%s",
              tostring(value), task.ppid or "?",
              task.euid or "?", task.egid or "?",
              task and task.cmd or "?",
              #props > 0 and ", "..table.concat(props,", ") or "",
              tostring(cgr), err_code, err,
              #info > 0 and " "..table.concat(info," ") or "" )
      end
      return
    end -- cgr and file == "tasks"

    ----------------------------------------------------------------------------
    -- End handling error: Task could not be added to a cgroup
    ----------------------------------------------------------------------------

    -- other error
    if LOG_WARNING then u_warning(
          "Can't write string '%s' into %s: (%d) %s",
          tostring(value), filepath, err_code,err ) end
  end -- sysfs_write_error

end -- do

--! @brief Write string to a file under SYSFS
function sysfs_write(path, value, quiet)
  local ok = nil
  local fp, err, err_code = io.open(path, "w")
  if not fp and not quiet then
    sysfs_write_error(path, value, err, err_code)
  else
    fp:setvbuf("no")
    ok, err, err_code = fp:write(value)
    if not ok and not quiet then
      sysfs_write_error(path, value, err, err_code)
    end
    fp:close()
  end

  return ok, err, err_code
end

function re_from_table(tab)
  return table.concat(tab, "|")
end


function to_string(data, indent)
    local str = ""

    if(indent == nil) then
        indent = 0
    end

    -- Check the type
    if(type(data) == "string") then
        str = str .. (" "):rep(indent) .. data .. "\n"
    elseif(type(data) == "number") then
        str = str .. (" "):rep(indent) .. data .. "\n"
    elseif(type(data) == "boolean") then
        if(data == true) then
            str = str .. "true"
        else
            str = str .. "false"
        end
    elseif(type(data) == "table") then
        local i, v
        for i, v in pairs(data) do
            -- Check for a table in a table
            if(type(v) == "table") then
                str = str .. (" "):rep(indent) .. i .. ":\n"
                str = str .. to_string(v, indent + 2)
            else
                str = str .. (" "):rep(indent) .. i .. ": " .. to_string(v, 0)
            end
        end
    else
        return tostring(data).."\n"
    end

    return str
end


function pprint(data)
  print(to_string(data))
end


function num_or_percent(conf, value, default)
  local rv = false
  if not conf and default then
    conf = default
  end
  if not conf then
    conf = "100%"
  end
  for w in string.gmatch(conf, "(%d+)%%") do
     return ((value)/100)*tonumber(w)
  end
  if not conf then
    return value
  end
  return conf
end


--! @} End of "addtogroup lua_HELPERS"
