posix = require("posix")

-- monkey patching lua core

function string:split(sep)
        local sep, fields = sep or ":", {}
        local pattern = string.format("([^%s]+)", sep)
        self:gsub(pattern, function(c) fields[#fields+1] = c end)
        return fields
end

function table.copy(t)
  local t2 = {}
  for k,v in pairs(t) do
    t2[k] = v
  end
  return t2
end

function table.merge(t, t2)
  for k,v in pairs(t2) do
    t[k] = v
  end
  return t
end


-- logging shortcuts
function ulatency.log_debug(msg)
  ulatency.log(ulatency.LOG_LEVEL_DEBUG, msg)
end

function ulatency.log_info(msg)
  ulatency.log(ulatency.LOG_LEVEL_INFO, msg)
end

function ulatency.log_warning(msg)
  ulatency.log(ulatency.LOG_LEVEL_WARNING, msg)
end

function ulatency.log_error(msg)
  ulatency.log(ulatency.LOG_LEVEL_ERROR, msg)
end

function ulatency.log_critical(msg)
  ulatency.log(ulatency.LOG_LEVEL_CRITICAL, msg)
end

function re_from_table(tab)
  return table.concat(tab, "|")
end

function ulatency.list_processes_group(key)
  procs = ulatency.list_processes()
  rv = {}
  for i, proc in ipairs(procs) do
    c = rv[proc[key]]
    if not c then
      rv[proc[key]] = { proc }
    else
      c[#c+1] = proc
    end
  end
  return rv
end

function ulatency.add_adjust_flag(lst, match, adj)
   for i, flag in ipairs(lst) do
     for k, v in pairs(match) do
       if flag[k] ~= v then
         flag = nil
        break
      end
    end
    if flag then
      for k, v in pairs(adj) do
        flag[k] = v
      end
      return flag, true
    end
  end
  local flag = ulatency.new_flag(match)
  for k, v in pairs(adj) do
    flag[k] = v
  end
  return flag, false
end

function ulatency.find_flag(lst, match)
  for i, flag in ipairs(lst) do
    for k, v in pairs(match) do
      if flag[k] ~= v then
        flag = nil
        break
      end
    end
    if flag then
      return flag
    end
  end
end

-- CGroups interface

if ulatency.get_uid() > 0 or 
   ulatency.get_config("logging", "disable_cgroup") then
  ulatency.log_info("disable cgroups error logging. not running as root")
  function cg_log(...)
  end
else
  cg_log = ulatency.log_warning
end



local function mkdirp(path)
  if posix.access(path) ~= 0 then
    local parts = path:split("/")
    for i,v in ipairs(parts) do
      name = "/" .. table.concat(parts, "/", 1, i)
      if posix.access(name, posix.R_OK) ~= 0 then
        if posix.mkdir(name) ~= 0 then
          cg_log("can't create "..name)
        end
      end
    end
  end
end



local _CGroup_Cache = {}

CGroup = {}

function CGroup_tostring(data, key)
  return "<CGroup ".. data.name ..">"
end


function CGroup_index(data, key)
  print("index", data, key)

end

ROOT_PATH = ulatency.get_config("core", "mount_point")
if string.sub(ROOT_PATH, -1) ~= "/" then
  ROOT_PATH = ROOT_PATH .. "/"
end

-- try mounting the mountpoints
mkdirp(ROOT_PATH)

-- FIXME move to config file

MNT_PNTS = {
  cm="cpu,memory,cpuset",
  io="blkio"
}

for n,v in pairs(MNT_PNTS) do
  mkdirp(ROOT_PATH..n)
  prog = "/bin/mount -t cgroup -o "..v.." none "..ROOT_PATH..n.."/"
  ulatency.log_info("mount cgroups: "..prog)
  fd = io.popen(prog, "r")
  print(fd:read("*a"))
end

-- FIXME we need some better solution for that :-/
-- cpuset, very powerfull, but can't create a group with unset cpus or mems
CGROUP_DEFAULT = {
  cm={["cpuset.cpus"] = "0-"..tostring(ulatency.smp_num_cpus-1),
      ["cpuset.mems"] = "0"
    },
}




CGroupMeta = { __index = CGroup, __tostring = CGroup_tostring}


function CGroup.new(name, init, tree)
  rv = _CGroup_Cache[name]
  if rv then
    return rv
  end
  tree = tree or "cm"
  if CGROUP_DEFAULT[tree] then
    cinit = table.copy(CGROUP_DEFAULT[tree])
  else
    cinit = {}
  end
  uncommited=table.merge(cinit, init or {})
  rv = setmetatable( {name=name, uncommited=uncommited, new_tasks={}, tree=tree, adjust={}}, CGroupMeta)
  _CGroup_Cache[name] = rv
  return rv
end

function CGroup.get_groups()
  return _CGroup_Cache
end

function CGroup.get_group(name)
  return _CGroup_Cache[name]
end


function CGroup:path(file)
  if file then
    return ROOT_PATH .. self.tree .. "/".. self.name .. "/" .. tostring(file)
  else
   return ROOT_PATH .. self.tree .. "/" .. self.name
  end
end

function CGroup:path_parts()
  return self.name:split("/")
end

function CGroup:parent()
  parts = self.name:split("/")
  name = table.concat(parts, "/", 1, #parts-1)
  if _CGroup_Cache[name] then
    return _CGroup_Cache[name]
  end
  return CGroup.new(name)
end

function CGroup:get_value(key, raw)
  uncommited = rawget(self, "uncommited")
  if uncommited[key] and not raw then
    return uncommited[key]
  end
  local path = self:path(key)
  if posix.access(path) == 0 then
    local fp = io.open(path, "r")
    return fp:read("*a")
  end
end


function CGroup:set_value(key, value)
  uncommited = rawget(self, "uncommited")
  uncommited[key] = value
end

function CGroup:get_tasks()
  local t_file = self:path("tasks")
  if posix.access(t_file, posix.R_OK) ~= 0 then
    return {}
  end
  rv = {}
  for line in io.lines(t_file) do
    rv[#rv+1] = tonumber(line)
  end
  return rv
end

function CGroup:run_adjust(proc)
  adjust = rawget(self, "adjust")
  for i,v in ipairs(adjust) do
    v(self, proc)
  end
end

--function CGroup:adjust()
--  return rawget(self, "adjust")
--end


function CGroup:add_task(pid, instant)
  nt = rawget(self, "new_tasks")
  if not nt then
    nt = {}
    rawset(self, "new_tasks", nt)
  end
  nt[#nt+1] = pid
  --pprint(nt)
  if instant then
    --print("instant")
    local t_file = self:path("tasks")
    fp = io.open(t_file, "w")
    --print(t_file)
    if fp then
      fp:write(tostring(pid))
    --  print("write")
      fp:close()
    else
      cg_log("can't attach "..pid.." to group "..t_file)
    end
  end
end

function CGroup:is_dirty()
  if #rawget(self, "uncommited") > 0 or
     #rawget(self, "new_tasks") > 0 or 
     posix.access(self:path()) ~= 0 then
     return true
  end
  return false
end

function CGroup:commit()
  mkdirp(self:path())
  uncommited = rawget(self, "uncommited")
  for k, v in pairs(uncommited) do
    path = self:path(k)
    fp = io.open(path, "w")
    if fp then
      --print("write"..path)
      fp:write(v)
      fp:close()
      uncommited[k] = nil
    else
      cg_log("can't write into :"..tostring(path))
    end
  end
  local t_file = self:path("tasks")
  fp = io.open(t_file, "w")
  if fp then
    pids = rawget(self, "new_tasks")
    if pids then
      while true do
        pid = table.remove(pids, 1)
        if not pid then
          break
        end
        fp:write(pid)
      end
      fp:close()
    end
  end
end

function CGroup:add_children(proc, fnc)
  function add_childs(list)
    for i,v in pairs(list) do
      self:add_task(v.pid)
      if fnc then
        fnc(v)
      end
    end
    for i,v in pairs(list) do
      add_childs(v.children)
    end
  end
  add_childs(proc.children)
end


function CGroup.create_isolation_group(proc, children)
  ng = CGroup.new("iso_"..tostring(pid))
  ng.commit()
  ng.add_task(proc.pid)
  proc:set_block_scheduler(1)

end

function CGroup:starve(what)
  if what == "memory" then
    nv = self:get_value("memory.usage_in_bytes", true)
    if nv then
      self:set_value("memory.limit_in_bytes", nv)
    end
  end
end





-- helper classes

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
