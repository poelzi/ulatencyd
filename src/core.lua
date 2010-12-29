print("core")

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


-- CGroups interface


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

function CGroup:get_value(key, value)
  uncommited = rawget(self, "uncommited")
  if uncommited[key] then
    return uncommited[key]
  end
  local path = self:path(key)
  if posix.access(path) then
    local fp = open(path, "r")
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
  uncommited = pairs(rawget(self, "uncommited")) 
  for k, v in uncommited do
    path = self:path(k)
    fp = io.open(path, "w")
    if fp then
      fp:write(v)
      fp:close()
      uncommited[k] = nil
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
