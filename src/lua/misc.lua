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
--! @return boolean
--! @retval 0 if the directory was successfully created.
--! @retval nil, errstr, errno if creation of some directory along the `path` failed.
function mkdirp(path)
  if not posix.access(path, "f") then
    local parts = path:split("/")
    for i,v in ipairs(parts) do
      name = "/" .. table.concat(parts, "/", 1, i)

      if not posix.access(name, "f") then -- this fail if `name`
                  -- (e.g /sys/fs/cgroup/cpu) is a symlink not created by root
        local ok, errstr, errno = posix.mkdir(name)
        if not ok then
          cg_log(string.format(
                "mkdirp(%s): Can't create directory: %s",
                path, errstr))
          return nil, errstr, errno
        end
      end

    end
  end
  return 0
end


--! @brief Log error after writing to sysfs failed: decides whether the error should be logged,
--! the log level and composes the error message.
--! @param filepath The file full path
--! @param value A value that trigger the error
--! @param err Textual representation of the error
--! @param err_code The error code (a number)
function sysfs_write_error(filepath, value, err, err_code)

  local s,e = string.find(filepath, CGROUP_ROOT, 1, true)
  if s == 1 then

    -- error while writing to a cgroup subsystem
    local fields = string.split(string.sub(filepath, e+1), '/')
    if #fields >= 2 then
      local subsys = fields[1]
      local file = fields[#fields]
      local cgr_name = #fields >= 3 and table.concat(fields, '/', 2, #fields-1) or ""
      local cgr = CGroup.get_group(subsys ..'/'.. cgr_name)
      if cgr then
        -- error while adding task to a cgroup
        if file == "tasks" then
          local proc = ulatency.get_pid(value)
          -- no such process; ignore this error
          if err_code == 3 then
            return
          end
          -- error while moving rt task between cgroups in cpu subsystem on kernel without CONFIG_RT_GROUP_SCHED
          if cgr.tree == "cpu" and err_code == 22 and posix.access(cgr:path("cpu.rt_runtime_us")) ~= 0 then
            local task = ulatency.get_tid(value)
            if task and (task.sched == ulatency.SCHED_RR or task.sched == ulatency.SCHED_FIFO) then
              ulatency.log_debug(string.format(
                "Task (tid: %s, RT sched.) couldn't be moved to %s (%d: %s) (probably kernel w/o CONFIG_RT_GROUP_SCHED)",
                tostring(value), tostring(cgr), err_code, err
              ))
              return
            end
          end
          -- other error
          ulatency.log_warning(string.format(
                "Task (tid: %s, cmdfile: %s, exe: %s) couldn't be moved to %s (%d: %s)",
                tostring(value), proc.cmdfile or "NONE", proc.exe or 'NONE',
                tostring(cgr), err_code, err))
          return
        end
      end
    end
  end

  ulatency.log_warning(string.format("can't write string '%s' into %s: (%d) %s",tostring(value),filepath,err_code,err))
end


--! @brief Write string to a file under SYSFS
function sysfs_write(path, value, quiet)
  local ok, err, err_code = false, nil, nil
  local fp = io.open(path, "w")
  if fp then
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
