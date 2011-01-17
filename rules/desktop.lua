--[[
    Copyright 2010,2011 ulatencyd developers

    This file is part of ulatencyd.

    License: GNU General Public License 3 or later
]]--

DesktopBG = {
  name = "UserBG",
  re_basename = "pulseaudio|mpd|xmms2d",
  check = function(self, proc)
    local flag = ulatency.new_flag{name="user.bg_high", inherit=true}
    proc:add_flag(flag)

    rv = ulatency.filter_rv(ulatency.FILTER_STOP)
    return rv
  end
}

local MediaPlayer = {
  "vlc",
  "xine",
  "mplayer.*",
  "dragon",
  "totem",
  "kplayer",
  -- audio players
  "amarok",
  "parole",
  "listen",
  "rhythmbox",
  "exaile",
}


DesktopMedia = {
  name = "DesktopMedia",
  re_basename = re_from_table(MediaPlayer),
  check = function(self, proc)
    local flag = ulatency.new_flag{name="user.media"}
    proc:add_flag(flag)

    rv = ulatency.filter_rv(ulatency.FILTER_STOP)
    return rv
  end
}


DesktopEssential = {
  name = "DesktopEssential",
  re_cmdline = "/usr/bin/X",
  check = function(self, proc)
    local flag = ulatency.new_flag{name="system.essential"}
    proc:add_flag(flag)

    rv = ulatency.filter_rv(ulatency.FILTER_STOP)
    return rv
  end
}


ulatency.register_filter(DesktopBG)
ulatency.register_filter(DesktopMedia)
ulatency.register_filter(DesktopEssential)
