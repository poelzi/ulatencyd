

SystemIdle = {
  name = "SystemIdle",
  --re_basename = "preload",
  re_basename = "preload",
  check = function(self, proc)
    local flag = ulatency.new_flag{name="daemon.idle", inherit=true}
    proc:add_flag(flag)

    rv = ulatency.filter_rv(ulatency.FILTER_STOP)
    return rv
  end
}

SystemBg = {
  name = "SystemBg",
  re_basename = "cron|anacron",
  check = function(self, proc)
    local flag = ulatency.new_flag{name="daemon.bg", inherit=true}
    proc:add_flag(flag)

    rv = ulatency.filter_rv(ulatency.FILTER_STOP)
    return rv
  end
}

ulatency.register_filter(SystemIdle)
ulatency.register_filter(SystemBg)
