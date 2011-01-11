local physical_ram = false
local memory_pressure = false


-- tracker of swapout
local vminfo = ulatency.get_vminfo()
local meminfo = ulatency.get_meminfo()
local swapout_stats_last = vminfo.vm_pswpout
local swapout_stats = {}

function num_or_percent(conf, value, default)
  local rv = false
  if not conf and default then
    conf = default
  end
  for w in string.gmatch(conf, "(%d+)%%") do
     return ((value)/100)*tonumber(w)
  end
  if not conf then
    return value
  end
  return conf
end

--pprint(meminfo)
--pprint(vminfo)

function update_caches()
  memory_pressure = false
  vminfo = ulatency.get_vminfo()
  meminfo = ulatency.get_meminfo()
  table.insert(swapout_stats, 1, vminfo.vm_pswpout - swapout_stats_last)
  swapout_stats_last = vminfo.vm_pswpout
  swapout_stats[10] = nil
  local swap_memory_pressure = true
  for i,j in ipairs(swapout_stats) do
    if j == 0 then swap_memory_pressure = false end
  end
  local min_free = num_or_percent(ulatency.get_config("memory", "min_free_ram"), 
                                  meminfo.kb_main_total)

  if (tonumber(meminfo.kb_main_cached) + tonumber(meminfo.kb_main_free)) <= min_free then
    memory_pressure = true
  end

  memory_pressure = swap_memory_pressure or memory_pressure
  if memory_pressure then
    ulatency.log_warning("memory pressure detected !")
  end
  return true
end

update_caches()
--ulatency.quit_daemon() 

local max_targets = ulatency.get_config("memory", "top_targets") or 0
if max_targets then
  max_targets = tonumber(max_targets)
end

local max_rss = num_or_percent(ulatency.get_config("memory", "rss_upper_limit"), 
                               meminfo.kb_main_total,
                               false)

ProtectorMemory = {
  name = "ProtectorMemory",
  
  targets = {},
  sure_targets = {},
  
  precheck = function(self)
    print("precheck")
    self.targets = {}
    self.sure_targets = {}
    return memory_pressure
  end,
  check = function(self, proc)
    self.targets[#self.targets+1] = proc
    table.sort(self.targets, 
               function(a, b)
                if a.is_invalid or b.is_invalid then
                  return false
                end
                return a.rss > b.rss
               end)
    self.targets[max_targets+1] = nil

    if max_rss then
      if proc.rss >= max_rss then
        self.sure_targets[#self.sure_targets+1] = proc
      end
    end
    return 0
  end,
  postcheck = function(self)
    pprint(self.targets)
    pprint(self.sure_targets)
    local flag = ulatency.new_flag{name="user.poison", reason="memory", 
                                   timeout=ulatency.get_time(500),}
    
    local added = 0
    local min_add = tonumber(ulatency.get_config("memory", "min_add_targets"))
    for i,proc in ipairs(self.sure_targets) do
      if proc.is_valid then
        proc:clear_flag_source()
        proc:add_flag(flag)
        added = added + 1
      end
    end
    for i,proc in ipairs(self.targets) do
      if added >= min_add then
        break
      end
      if proc.is_valid then
        proc:clear_flag_source()
        proc:add_flag(flag)
      end
    end
    rv = ulatency.filter_rv(ulatency.FILTER_STOP)
  end,
  
}

ulatency.register_filter(ProtectorMemory)
ulatency.add_timeout(update_caches, 1000)