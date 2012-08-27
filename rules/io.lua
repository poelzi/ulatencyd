--[[
IO rules

these are optimizers for IO
]]--

posix = require("posix")

BottleNeck = {
  -- detects high loads on discs and enables the cgroup group_isolation
  -- when the treshold is over a limited time
  -- group_isolation is only good on heavy io load
  last_data = {},
  history = {},
  -- list of entries to be ignored (partitions)
  ignored = {},
  first_run = true,
  window = tonumber(ulatency.get_config("io", "window") or 10),
  threshold = tonumber(ulatency.get_config("io", "threshold") or 100000),
  percent = tonumber(ulatency.get_config("io", "percent") or 50) ,
  last_set = {},

  calc_history = function(self, old, new)
    -- calculates if the threshold was reached and puts the result into the history

    function check(old, new)
      if new < old then -- overflow, better be safe :-)
        return true
      end
      if new >= old + self.threshold then
        return true
      end
      return false
    end

    result = check(tonumber(old[14]), tonumber(new[14]))

    local h = self.history[old[3]]
    table.insert(h, 1, result)
    h[self.window+1] = nil
  end,

  add_entry = function(self, chunks)
    local dev = chunks[3]

    if self.ignored[dev] then
      return
    end

    if self.first_run == true then
      self:set_scheduler(dev, ulatency.get_config("io", "scheduler") or "cfq")
    end

    if not self.history[dev] then
      if posix.access(ulatency.mountpoints["sysfs"] .. "/block/"..dev) == 0 then
        self.history[dev] = {}
      else
        self.ignored[dev] = true
      end
    end
    if self.last_data[dev] then
      self:calc_history(self.last_data[dev], chunks)
    end
    self.last_data[dev] = chunks
  end,

  set_scheduler = function(self, dev, scheduler)
    local path = ulatency.mountpoints["sysfs"] .. "/block/" .. dev .. "/queue/scheduler"
    local fp = io.open(path, "w")
    if not fp then
      return
    end
    fp:write(tostring(scheduler))
    fp:close()
  end,

  set_isolation = function(self, dev, value)
    if self.last_set[dev] == value then
      return
    end
    ulatency.log_debug("IO: set group isolation on dev "..dev.." to "..tostring(value))
    self.last_set[dev] = value
    local path = ulatency.mountpoints["sysfs"] .. "/block/" .. dev .. "/queue/iosched/group_isolation"
    local fp = io.open(path, "w")
    if not fp then
      return
    end
    fp:write(tostring(value))
    fp:close()
  end,

  parse_data = function(self)
    local fp = io.open("/proc/diskstats", "r")
    if not fp then
      return
    end
    for line in fp:lines() do
      local chunks = string.split(line, " ")
      self:add_entry(chunks)
    end
    fp:close()
    self.first_run = false
  end,

  decide = function(self)
    for dev, history in pairs(self.history) do
      if #history == self.window then
        local yes = 0
        for n, x in ipairs(history) do
          if x then
            yes = yes +1
          end
        end
        if (yes * 100) >= (#history * self.percent) then
          self:set_isolation(dev, 1)
        else
          self:set_isolation(dev, 0)
        end
      end
    end
  end,

  iterate = function(self)
    -- called from timeout function
    self:parse_data()
    self:decide()
  end

}

local function iterate()
  -- called from timeout function
  BottleNeck:iterate()
  return true
end

if ulatency.tree_loaded("blkio") then
  ulatency.add_timeout(iterate, 1000)
end

if ulatency.tree_loaded("bfqio") then
  ulatency.add_timeout(iterate, 1000)
end
