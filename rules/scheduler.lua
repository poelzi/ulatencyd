
require("posix")

u_groups = {}


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

ul_group = CGroup.new("s_ul", { ["cpu.shares"]="500", ["memory.swappiness"] = "0" })
local UL_PID = posix.getpid()["pid"]
print("ul_pid"..UL_PID)
ul_group:add_task(UL_PID)
ul_group:commit()

ITER = 1


-- WARNING: don't use non alpha numeric characters in name
-- FIXME: build validator

MAPPING = { 
  ESSENTIAL = {
    name = "system_essential",
    cgroups_name = "s_essential",
    param = { ["cpu.shares"]="3048" },
    label = { "system.essential" }
  },
  USER = {
    name = "user",
    cgroups_name = "u_${euid}",
    check = function(proc)
              return ( proc.euid > 999 )
            end,
    param = { ["cpu.shares"]="3048" },
    children = {
      POISON = { 
        name = "poison",
        param = { ["cpu.shares"]="10" },
        label = { "user.poison" }
      },
      MEDIA = { 
        name = "bg_high",
        param = { ["cpu.shares"]="1024" },
        label = { "user.bg_high" },
        check = function(proc)
                  print("classived, ui.bg_high", proc)
                  return true
                end,
      },
      MEDIA = { 
        name = "media",
        param = { ["cpu.shares"]="2048" },
        label = { "user.media" },
        check = function(proc)
                  print("classived, ui.media", proc)
                  return true
                end,
      },
      UI = { 
        name = "ui",
        param = { ["cpu.shares"]="2048" },
        label = { "user.ui" }
      },
      IDLE = { 
        name = "idle",
        param = {  },
      },
      SESSION = { 
        name = "session",
        param = { ["cpu.shares"]="600" },
        cgroups_name = "${session}",
        check = function(proc)
                  return true
                end,
      },
    },
  },
  SYSTEM = {
    name = "system",
    cgroups_name = "s_daemon",
    check = function(proc)
              -- don't put kernel threads into a cgroup
              return (proc.ppid ~= 0 or proc.pid == 1)
            end,
    param = { ["cpu.shares"]="800" },
  },
}
  
pprint(MAPPING)

function check_label(labels, proc)
  for j, flag in pairs(proc:list_flags()) do
    for k, slabel in pairs(labels) do
      if flag.name == slabel then
        return true
      end
    end
  end
end

function check(proc, rule)
  assert(proc)
  if rule.label then
    if check_label(rule.label, proc) then
      pprint("match label"..tostring(proc))
      pprint(rule.label)
      return rule
    end
  elseif rule.check then
    if rule.check(proc) then
      return rule
    end
  end
  return nil
end

function run_list(proc, lst)
  local rv = {}
  for key, rule in pairs(lst) do
    match = check(proc, rule)
    if match then
      rv[#rv+1] = match
      if match.children then
        best_subs = run_list(proc, match.children)
        --print("got bestsubs", type(best_subs), best_subs, #best_subs)
        if best_subs and #best_subs > 0 then
          for i,sub in ipairs(best_subs) do
            rv[#rv+1] = sub
          end
        end
      end
      break
    end
  end
  return rv
end

local function format_name(proc, map)
  -- generates the final path for the process for the map
  if map.cgroups_name then
    function get(name)
      local rv2 = proc[name]
      rv2 = tostring(rv2)
      return rv2
    end
    return string.gsub(map.cgroups_name, "%$\{(%w+)\}", get)
  end
  return map.name
end

local function build_path_parts(proc, res)
  -- build a array for 
  local rv = {}
  for i,k in ipairs(res) do
    local cname = format_name(proc, k)
    rv[#rv+1] = cname
  end
  return rv
end

local function create_group(proc, prefix, mapping)
  name = format_name(proc, mapping)
  if #prefix > 0 then
    path = prefix .. "/" .. name
  else
    path = name
  end
  return CGroup.new(path, mapping.param)
end

local function map_to_group(proc, parts)
  local chain = build_path_parts(proc, parts)
  local path = table.concat(chain, "/")
  local cgr = CGroup.get_group(path)
  if cgr then
    return cgr
  end

  local prefix = ""
  for i, parrule in ipairs(parts) do
    --local parent = create_group(proc, prefix, 
    cgr = create_group(proc, prefix, parrule)
    prefix = cgr.name
  end
  print("final prefix", prefix)
  --CGroup.new(mapping.name, )n-ar
  return cgr
end


Scheduler = {}

local ALL = false
function Scheduler:all()
  local group

  -- list only changed processes
  for k,proc in ipairs(ulatency.list_processes(ALL)) do
--    print("sched", proc, proc.cmdline)
    self:one(proc)
  end
  for k, v in pairs(CGroup.get_groups()) do
    v:commit()
  end
  ALL = true
  return true
end

function Scheduler:one(proc)
  if proc.block_scheduler == 0 then
    -- we shall not touch us
    if proc.pid == UL_PID then
      proc:clear_changed()
      return true
    end
    local mappings = run_list(proc, MAPPING)
    --pprint(res)
    group = map_to_group(proc, mappings)
    --print(tostring(proc.pid) .. " : ".. tostring(group))
    if group then
      if group:is_dirty() then
        group:commit()
      end
      group:add_task(proc.pid, true)
      proc:clear_changed()
    end
    --pprint(build_path_parts(proc, res))
  end
  return true
end



function byby()
  ulatency.quit_daemon()

end

--ulatency.add_timeout(byby, 100000)

ulatency.scheduler = Scheduler





--[[

-- OLD libcgroup cra

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
