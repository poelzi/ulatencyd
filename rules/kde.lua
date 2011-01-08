
local Kde_Ui_Tab = {
  "kuiserver",
  "kwalletmanager",
  "knotify4",
  "kmix",
  "kded4",
  "kwin",
  "plasma"
}


KdeUI = {
  name = "KdeUI",
  re_basename = re_from_table(Kde_Ui_Tab),
  --re_basename = "metacity",
  check = function(self, proc)
    local flag = ulatency.new_flag{name="user.ui"}
    proc:add_flag(flag)

    rv = ulatency.filter_rv(ulatency.FILTER_STOP)
    return rv
  end
}

ulatency.register_filter(KdeUI)
