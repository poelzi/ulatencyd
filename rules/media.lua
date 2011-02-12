--[[
    Copyright 2010,2011 ulatencyd developers

    This file is part of ulatencyd.

    License: GNU General Public License 3 or later
]]--

MediaPlayer = {
  name = "MediaPlayer",
  re_cmdline = "mplayer|xine|vlc",
  --re_basename = "metacity",
  check = function(self, proc)
    local flag = ulatency.new_flag("user.media")
    proc:add_flag(flag)
    rv = ulatency.filter_rv(ulatency.FILTER_STOP)
    return rv
  end,
}


Jackd = {
  name = "Jackd",
  re_cmdline = "jackd",
  --re_basename = "metacity",
  check = function(self, proc)
    local flag = ulatency.new_flag("user.bg_high")
    proc:add_flag(flag)
    rv = ulatency.filter_rv(ulatency.FILTER_STOP)
    return rv
  end,
}

ulatency.register_filter(Jackd)
ulatency.register_filter(MediaPlayer)
