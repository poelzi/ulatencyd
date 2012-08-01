-- one of last rules to execute, depends on flags set by previous rules

--! @file zz_isolate.lua
--! Implements the Isolate filter.
--! @ingroup lua_FLAG_FILTERS

--! @class Isolate
--! @brief This filter isolates processes that are labelled with the __ISOLATE_FLAG.
--! The @link Isolate.check() `check()`@endlink function isolates matched processes according the 
--! @link __ISOLATE_FLAG flag values@endlink and eventual per application @link Isolate.RULES rules@endlink.
--! @note The processes are usually flagged by @link lua_SIMPLERULES simplerules@endlink configuration file
--! `conf/simple.d/isolate.conf`.
--! @implements __FILTER
--! @ingroup lua_FLAG_FILTERS
Isolate = {
  --! @public @memberof Isolate
  name = "Isolate",

  --! @brief Puts processes labeled with the `{name = "isolate"}` u_flag to the isolation by calling the
  --! `CGroup.create_isolation_group()` function.
  --! @details A process to be affected by this filter must be labelled with the flag with the name "isolate" and 
  --! threshold greater than 1. Threshold and reason values defines how the process will be isolated. See 
  --! __ISOLATE_FLAG for detailed description of the flag values and how they are interpreted by this filter.
  --! @return `ulatency.filter_rv(ulatency.FILTER_STOP)`
  --! @public @memberof Isolate
  check = function(self, proc)
    -- we give processes marked with media flags good io prio
    local flg = ulatency.find_flag(proc:list_flags(), {name="isolate"})
    if flg and flg.threshold and flg.threshold > 0 then
      ulatency.log_info(string.format('isolating process %d (%s), euid: %d, cmdline: %s',
                            proc.pid, proc.cmdfile, proc.euid, proc.cmdline_match))
      if flg.reason and flg.reason ~= "" then
        CGroup.create_isolation_group(proc, flg.reason, self.RULES[flg.reason] or {}, false, flg.threshold)
      else
        proc:set_block_scheduler(flg.threshold)
      end
    end
    rv = ulatency.filter_rv(ulatency.FILTER_STOP)
    return rv
  end
}

-- [RULES]
Isolate.RULES = {
  ["ulatency"] = {
    cpu = { params = {["cpu.shares"]="500"} },
    memory = { params = {["?memory.swappiness"]="0"} }
  }
}
-- [RULES]

ulatency.register_filter(Isolate)