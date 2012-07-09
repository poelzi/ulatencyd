-- last rules to execute, they can depend on flags set by previous rules

MediaIO = {
  name = "MediaIO",
  check = function(self, proc)
    -- we give processes marked with media flags good io prio
    if ulatency.find_flag(proc:list_flags(), {name="user.media"}) then
      proc:set_ioprio(7, ulatency.IOPRIO_CLASS_RT)
    end

    rv = ulatency.filter_rv(ulatency.FILTER_STOP)
    return rv
  end
}

ulatency.register_filter(MediaIO)
