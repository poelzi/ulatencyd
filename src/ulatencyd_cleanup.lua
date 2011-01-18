#!/usr/bin/env lua
MNT_PNTS = {"cm", "io"}
CGROUP_ROOT = "/dev/cgroup/"

require("posix")

if not arg[1] then
  print "path required"
  os.exit(1)
end

for i, mnt in ipairs(MNT_PNTS) do
  local path = CGROUP_ROOT .. mnt .. "/" .. arg[1]
  if posix.access(path) == 0 then
    if posix.rmdir(path) == 0 then
      os.exit(0)
    end
  end
end

os.exit(1)
