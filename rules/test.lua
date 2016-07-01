flag = ulatency.new_flag{name="test", reason="dbus"}
ulatency.add_flag(flag)
flag = ulatency.new_flag{name="test", reason="need more data", value=32, threshold=666}
ulatency.add_flag(flag)

print("-------")
pprint(ulatency.get_sessions())
print("-------")

PrintProcTest = {
  name = "Test",
  --re_basename = "preload",
  check = function(self, proc)
    if proc.ppid > 0 then
      --pprint(proc.cmdline)
      --print("cf", proc.cmdfile)
      print("cmd",proc, proc.sched, proc.rtprio, proc.cmd)
      for i,v in ipairs(proc:get_tasks()) do
        print(v.tid, v.rtprio, v.sched)
      end
      print(proc.received_rt)
      --print(proc:get_tasks()[1].tid)
      --print("exe", proc.exe)
      --print("tasks")
      --pprint(proc:get_tasks(true))
      --pprint(proc.cmdline_match)
      --pprint(proc.environ)
      --if proc.environ then
      --  print("HOME", proc.environ.HOME)
      --end
      --print("groups:")
      --pprint(proc.groups)
    end
    rv = ulatency.filter_rv(ulatency.FILTER_STOP)
    return rv
  end,
  postcheck = function()
    pprint(ulatency.search_uid_env(1000, "DBUS_SESSION_BUS_ADDRESS"))
  end
  
}

ulatency.register_filter(PrintProcTest)
