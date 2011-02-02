flag = ulatency.new_flag{name="test", reason="dbus"}
ulatency.add_flag(flag)
flag = ulatency.new_flag{name="test", reason="need more data", value=32, threshold=666}
ulatency.add_flag(flag)

print("-------")
pprint(ulatency.get_sessions())
print("-------")
act, idle = ulatency.get_uid_stats(1000)
print("act:", act, "idle:", idle)

PrintProcTest = {
  name = "Test",
  --re_basename = "preload",
  check = function(self, proc)
    if proc.ppid > 0 then
      print("---", proc.pid)
      pprint(proc.cmdline)
      print("cf", proc.cmdfile)
      print("cmd", proc.cmd)
      print("exe", proc.exe)
      pprint(proc.cmdline_match)
      --pprint(proc.environ)
      if proc.environ then
        print("HOME", proc.environ.HOME)
      end
      print("groups:")
      pprint(proc.groups)
    end
    rv = ulatency.filter_rv(ulatency.FILTER_STOP)
    return rv
  end,
  postcheck = function()
    pprint(ulatency.search_uid_env(1000, "DBUS_SESSION_BUS_ADDRESS"))
  end
  
}

ulatency.register_filter(PrintProcTest)
