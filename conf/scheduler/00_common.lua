--! @brief penelizes

function save_io_prio(proc, prio, class)
  if not proc.data.io_prio then
    proc.data.io_prio = {proc:get_ioprio()}
  end
  proc:set_ioprio(prio, class)
end

function restore_io_prio(proc)
  if proc.data.io_prio then
    local pr = proc.data.io_prio
    proc:set_ioprio(pr[1], pr[2])
  end
end
