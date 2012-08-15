--[[
    Copyright 2010,2011 ulatencyd developers

    This file is part of ulatencyd.

    License: GNU General Public License 3 or later
]]--

local active_uid = nil
local fallback = false

--! Safety net for not processed session changes.
--! @details Just runs full iteration whenever the active console-kit session changed and `system_flags_changed` not already set.
--! Normally the full iteration is invoked from session_active_changed() in sysinfo.c, but sometimes this fails.
--! @note This will be removed once this bug is fixed.
--! @ingroup lua_TIMEOUTS_IMPLEMENTED
function check_session_changed()
  if not ulatency.get_flags_changed() then
    local _, sess
    for _,sess in pairs(ulatency.get_sessions()) do
      if sess.active and sess.uid ~= active_uid then
        fallback = true
        ulatency.set_flags_changed(1) --just force full run
        ulatency.run_iteration()
      end
    end
  end
  return true
end

--! @class SessionChanged
--! @brief Safety net for not processed session changes.
--! @see `check_session_changed()` timeout
--! @note This will be removed once this bug is fixed.
--! @ingroup lua_FLAG_FILTERS
SessionChanged = {
  name = "SessionChanged",
  precheck = function(self)
    local _, sess
    for _,sess in pairs(ulatency.get_sessions()) do
      if sess.active and sess.uid ~= active_uid then
        -- active user changed, now we may be in one of following scenarios:
        active_uid = sess.uid
        if not ulatency.get_flags_changed() then
          -- REALLY STRANGE: system_flags_changed not set
          ulatency.log_warning(string.format(
            "Session change left unnoticed (changed to uid %d) (not catched by fallback timeout, fallback=%s)",
            active_uid, tostring(fallback)
          ))
          fallback = false
          ulatency.set_flags_changed(1) --just force full run
          ulatency.run_iteration()
        elseif fallback then
          -- BUG: system_flags_changed, fallback set - full iteration invoked by check_session_changed() timeout.
          fallback = false
          ulatency.log_warning(string.format("Session change left unnoticed (changed to uid %d) (catched by fallback timeout)", active_uid))
        end
        -- else OK: system_flags_changed, fallback not set - full iteration invoked by session_active_changed() in sysinfo.c
        break
      end
    end
    return false
  end,
  check = function(self, proc) -- never run, it's present only to avoid ulatency warning message
    return ulatency.filter_rv(ulatency.FILTER_STOP)
  end
}

ulatency.register_filter(SessionChanged)
ulatency.add_timeout(check_session_changed, 5000)