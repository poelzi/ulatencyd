ul = ulatency

print ("test run")

print (ulatency)
print (ulatency.version)

ld1,ld5,ld15 = ulatency.get_load()
print (ld1, ld5, ld15)

function print_table(tab)
  for k, v in pairs(tab) do
    print(k, v)
  end
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
                str = str .. (" "):rep(indent) .. i .. ": " ..
to_string(v, 0)
            end
        end
    else
        print_debug(1, "Error: unknown data type: %s", type(data))
    end

    return str
end

print(cgroups)
cg = cgroups.new_cgroup("bla")
print(cg)
cc = cg:add_controller("blubb")
print(cc)
cc:add_value("test", 3)
cc:add_value("test2", "eai")
cc:add_value("test3", true)
print("test", cc:get_value_int("test"))
print("test2", cc:get_value_string("test"))
print("test2", cc:get_value_string("test2"))
print("test3", cc:get_value_string("test3"))
print(to_string(cc:get_names()))
cg:create_cgroup()
print("done")



ulatency.quit_daemon()
--[[

TEST_PIDS = {23, 43, 53, 1231, 23, 123123, 235, 23}
TEST_I = 1

function test_active()
  if TEST_I > #TEST_PIDS then
    ulatency.quit_daemon()
  end
  ul.set_active_pid(1, TEST_PIDS[TEST_I])
  TEST_I = TEST_I + 1
  print("##")
  print(to_string(ul.get_active_pids(1)))
  print("--")
  return true
end

ulatency.add_timeout(test_active, 1000)

--ulatency.quit_daemon()

]]--
--[[
ld1,ld5,ld15 = ulatency.get_load()
print (ld1, ld5, ld15)

print_table(ulatency.get_meminfo())

print_table(ulatency.get_vminfo())

print(ulatency.get_pid_digits())
print(ulatency.hertz)
print(ulatency.smp_num_cpus)


proc = ul.get_pid(1)

function pr(str)
  print("proc", str, proc[str])
end

print(proc)
pr('tid')
pr('ppid')
pr('state')
pr('utime') 
pr('stime') 
pr('cutime') 
pr('cstime') 
pr('start_time') 

pr('signal') 

pr('blocked')
pr('sigignore')
pr('sigcatch')
pr('_sigpnd')

pr('cgroup_name')
pr('cmdline')
pr('environ')

print_table(ul.list_pids())
--
-- test_filter = {
--   process_re = "firefox.*"
-- }
--
-- fuction test_filter:check(process) {
--   print("check"..tostring(process)
-- }
--
-- ulatency.register_filter(test_filter)

si_run = 0
function someinterval(data)
  print("interval", data, si_run)
  if si_run == 2 then
    ul.quit_daemon()
    return false
  end
  si_run = si_run + 1
  return true
end

ulatency.add_timeout(someinterval, 10000)

TestFilter = {
  name = "TestFilter",
  re_basename = "init",
}

print(ul.get_config("TestFilter", "something"))
print_table(ul.list_keys("TestFilter"))

function TestFilter:check(proc)
  print("check process", proc)
  print(proc.cmdline)
  if(proc.cmdline == "/sbin/init") then
    return ul.FILTER_STOP
  end
end

ulatency.register_filter(TestFilter)

--ulatency.quit_daemon()
]]--