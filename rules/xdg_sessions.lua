--! @file xdg_sessions.lua
--! Determine if the process is member of a XDG session and tag with xdg_session label if it is.
--! @ingroup lua_FLAGGING_FILTERS

local function clear_flag_prefix(prefixes, proc)
    for _, flag in ipairs(proc:list_flags()) do
      for _, prefix in ipairs(prefixes) do
        if string.find(flag["name"], "^"..prefix.."\.") then
          proc:del_flag(flag)
          break
        end
      end
    end
end

--! @class XDG_sessions
--! @brief This filter tags processes that are members of XDG session with xdg_session label.
--! @details Currently only processes with EUID outside the range 1000 and 60000
--! are checked for the cookie; user processes are tagged as session members implicitly.
--! Values of session cookies are not stored, so you cannot determine which session the
--! process belongs to. For now, this functionality is sufficient, and adding more would probably
--! require some profiling.
--! @todo Use ulatency.FILTER_STOP + ulatency.FILTER_SKIP_CHILD as return values. Currently broken.
--! @todo Replace EUID based session management in ulatencyd with real XDG session management based approach.
--! @implements __FILTER
--! @ingroup lua_FLAGGING_FILTERS
XDG_sessions = {
  --! @public @memberof Sessions
  name = "XDG_sessions",
  --! @public @memberof Sessions
  check = function(self, proc)
    local has_session = true

    if proc.euid < 1000 or proc.euid > 60000 then
      has_session = proc.environ and proc.environ['XDG_SESSION_COOKIE']
      if not proc.environ then
        ulatency.log_warning(string.format('Cannot read environment of PID %d (%s), euid: %d, cmdline: %s',
          proc.pid, proc.cmdfile or "NONE", proc.euid, proc.cmdline_match or "<no cmdline>"))
        return ulatency.filter_rv(0, 600)
      end
    end

    if has_session then
      clear_flag_prefix({'system','daemon'}, proc)
    else
      clear_flag_prefix({'user'}, proc)
    end

    --[[ ulatency.FILTER_SKIP_CHILD is broken
    if has_session then
      local flag = ulatency.new_flag({name="xdg_session", inherit=true})
      proc:add_flag(flag)
      return ulatency.filter_rv(ulatency.FILTER_STOP + ulatency.FILTER_SKIP_CHILD)
    end
    ]]--

    if has_session and not ulatency.match_flag({"xdg_session"}, proc) then
      local flag = ulatency.new_flag({name="xdg_session", inherit=true})
      proc:add_flag(flag)
      return ulatency.filter_rv(ulatency.FILTER_STOP)
    end

    return ulatency.filter_rv(ulatency.FILTER_STOP)
  end
}

ulatency.register_filter(XDG_sessions)
