

GnomeUI = {
  name = "GnomeUI",
  re_basename = "metacity|compiz|gnome-panel",
  --re_basename = "metacity",
  check = function(self, proc)
    local flag = ulatency.new_flag("user.ui")
    proc:add_flag(flag)
    pprint(proc:list_flags())
    rv = ulatency.filter_rv(ulatency.FILTER_STOP)
    return rv
  end
}

ulatency.register_filter(GnomeUI)
--[[

print(ul.get_config("TestFilter", "something"))
print_table(ul.list_keys("TestFilter"))

function TestFilter:check(proc)
  print("check process", proc)
  print(proc.cmdline)
  if(proc.cmdline == "/sbin/init") then
    return ul.FILTER_STOP
  end
end


 = {
  
}
]]--