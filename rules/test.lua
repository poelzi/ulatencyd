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
  if si_run == 10 then
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


function TestFilter:check(proc)
  print("check process")
  print(proc) 
end

ulatency.register_filter(TestFilter)

--ulatency.quit_daemon()