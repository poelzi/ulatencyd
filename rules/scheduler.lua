
require("posix")

function is_user_uid(uid)
  return uid > 999
end

u_groups = {}


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



--[[
function mk_group(name)
  grp = cgroups.new_cgroup("/"..name)
  cpu = grp:add_controller("cpu")
  print("cpu", cpu)
  cpu:add_value("cpu.shares", 2048)
  return grp
end

function apply(srcgroup)
  print(srcgroup:get_name())
  grp = cgroups.new_cgroup(srcgroup:get_name())
  rv = grp:get_cgroup()
  if(rv ~= 0) then
    print("can't read kernel", rv)
  end
  
  rv = grp:copy_from(srcgroup)
  if(rv ~= 0) then
    print("can't copy source", rv)
  end
  rv = grp:modify_cgroup()
  if (rv ~= 0) then
    print("can't mod croups", rv)
  end

end


--u_groups[""] = mk_group("")
print("1")
--u_groups["s_daemon"] = root_group:create_cgroup_from_parent("/daemon")
u_groups["s_daemon"] = mk_group("s_daemon")
print("2")


function get_user_group(uid)
  name = "u_"..tostring(uid)
  grp = u_groups[name]
  if not grp then
    grp = mk_group(name)
    u_groups[name] = grp
    grp:create_cgroup()
  end
  return grp
end

--]]

local function mkdirp(path)
  if posix.access(path) ~= 0 then
    local parts = path:split("/")
    for i,v in ipairs(parts) do
      name = "/" .. table.concat(parts, "/", 1, i)
      if posix.access(name, posix.R_OK) ~= 0 then
        if posix.mkdir(name) ~= 0 then
          print("can't create "..name)
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

CGroupMeta = { __index = CGroup, __tostring = CGroup_tostring}

function string:split(sep)
        local sep, fields = sep or ":", {}
        local pattern = string.format("([^%s]+)", sep)
        self:gsub(pattern, function(c) fields[#fields+1] = c end)
        return fields
end


function CGroup.new(name, init)
  rv = _CGroup_Cache[name]
  if rv then
    return rv
  end
  rv = setmetatable( {name=name, uncommited = init or {}}, CGroupMeta)
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
    return ROOT_PATH .. self.name .. "/" .. tostring(file)
  else
   return ROOT_PATH .. self.name
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
 

function CGroup:set_value(key, value)
  uncommited = rawget(self, "uncommited")
  if not uncommited then
    uncommited = {}
    rawset(self, "uncommited", uncommited)
  end
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


function CGroup:add_task(pid, instant)
  nt = rawget(self, "new_tasks")
  if not nt then
    nt = {}
    rawset(self, "new_tasks", nt)
  end
  nt[#nt+1] = pid
  
  if instant then
    local t_file = self:path("tasks")
    fp = io.open(t_file, "w")
    if fp then
      fp:write(pid)
      fp:close()
    end
  end
end

function CGroup:commit()
  mkdirp(self:path())
  for k, v in pairs(rawget(self, "uncommited")) do
    path = self:path(k)
    fp = io.open(path, "w")
    if fp then
      fp:write(v)
      fp:close()
    else
      print("can't write into :"..tostring(path))
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


--[[

FIXME tests 

grp = CGroup.new("bla/blubb")
print("grp", grp)
print(grp:path())
print(grp:parent())
grp:set_value("cpu.shares", 1302)
grp:commit()
pprint(grp:get_tasks())
grp:add_task(1, true)
pprint(grp:get_tasks())

]]--

function get_user_group(uid)
  return CGroup.new("u_"..tostring(uid))
end


--ulatency.quit_daemon()

ITER = 1

function test_sched()
  local group
  for k,proc in ipairs(ulatency.list_processes()) do
    --print("sched", v)
    if is_user_uid(proc.euid) then
      group = get_user_group(proc.euid)
    else
      group = CGroup.new("s_daemon")
    end
    --print("attach", proc.pid, "old", proc.cgroups)
    if group then
      group:add_task(proc.pid, true)
    end
  end
  for k, v in pairs(CGroup.get_groups()) do
    v:commit()
  end
  return true
end

function byby()
  ulatency.quit_daemon()

end

--ulatency.add_timeout(byby, 100000)

ulatency.scheduler = test_sched
