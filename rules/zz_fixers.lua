-- last rules to execute, they can depend on flags set by previous rules

--! @file zz_fixers.lua
--! Implements the filters that manipulate processes flagged by previous rules.
--! @ingroup lua_FLAG_FILTERS

--! @class MediaIO
--! @brief This filter sets real-time I/O priority for processes tagged with `{name="user-media"}` flag.
--! @implements __FILTER
--! @ingroup lua_FLAG_FILTERS
MediaIO = {
  --! @public @memberof MediaIO
  name = "MediaIO",
  --! @return `ulatency.filter_rv(ulatency.FILTER_STOP)`
  --! @public @memberof MediaIO
  check = function(self, proc)
    -- we give processes marked with media flags good io prio
    if ulatency.find_flag(proc:list_flags(true), {name="user.media"}) then
      proc:set_ioprio(7, ulatency.IOPRIO_CLASS_RT)
    end

    rv = ulatency.filter_rv(ulatency.FILTER_STOP)
    return rv
  end
}

ulatency.register_filter(MediaIO)
