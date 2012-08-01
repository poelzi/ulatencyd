--[[
    Copyright 2010,2011 ulatencyd developers

    This file is part of ulatencyd.

    License: GNU General Public License 3 or later
]]--

local active_uid = ''

--! Just runs full iteration whenever the active console-kit session changed.
--! @details
--! @todo This should be better done in sysinfo.c handler for ck ActiveChanged signal (session_active_changed handler).
--! Or even better in seat handler.
--! @ingroup lua_TIMEOUTS_IMPLEMENTED
function check_session_changed()
  for i,sess in pairs(ulatency.get_sessions()) do
    if sess.active and sess.uid ~= active_uid then
      active_uid = sess.uid
      ulatency.log_info("active session changed to user " .. sess.uid)
      ulatency.set_flags_changed(1) --just force full run
      ulatency.run_iteration()
    end
  end
  return true
end

ulatency.add_timeout(check_session_changed, 1000)