--[[
    Copyright 2010,2011 ulatencyd developers

    This file is part of ulatencyd.

    License: GNU General Public License 3 or later
]]--

local Kde_Ui_Tab = {
  "kuiserver",
  "kwalletmanager",
  "knotify4",
  "kmix",
  "kded4",
  "kwin",
  "plasma-desktop"
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

KdeCore = {
  name = "KdeCore",
  re_basename = "startkde|kdeinit4|plasma-desktop",
  check = function(self, proc)
    if proc.cmd_file == "plasma-desktop" then
      -- plasma requires a lot of ram and is buggy sometimes, better we
      -- do not set it's oom adj to low
      proc:set_oom_score(-130)
    else
      proc:set_oom_score(-300)
    end

    return ulatency.filter_rv(ulatency.FILTER_STOP)
  end
}

-- kde does a very bad job in setting grpid's, causing the complete
-- desktop to be run under one group. we fix this problem here, ugly
-- but working

-- filter that instantly sets a fake group on newly spawned processes from
-- krunner und kdeinit4
KdeRunnerFix = RunnerFix.new("KdeRunnerFix", {"kdeinit4: kdeinit4 Running...", "krunner"})

-- on start we have to fix all processes that have descented from kde

local function cleanup_kde_mess()
  cleanup_desktop_mess({"kdeinit4: kdeinit4 Running...", "krunner"})
  return false
end

ulatency.add_timeout(cleanup_kde_mess, 1000)
ulatency.register_filter(KdeCore)
ulatency.register_filter(KdeUI)
ulatency.register_filter(KdeRunnerFix)

