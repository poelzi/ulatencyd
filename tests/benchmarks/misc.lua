module(..., package.seeall)

function test_match_flag()
  local flags = {
    ulatency.new_flag{name="hello"},
    ulatency.new_flag{name="hello2"},
    ulatency.new_flag{name="bla", value=3},
    ulatency.new_flag{name="bla", threshold=4, reason="blabla"},
  }
  
  print()

  -- system flags
  for _,flag in ipairs(flags) do
    ulatency.add_flag(flag)
  end
  benchmark("simple system flag search", 1e5,
    { "ulatency.match_flag", function() ulatency.match_flag({name = "bla", reason="blabla"}) end },
    { "ulatency.find_flag", function() ulatency.find_flag(ulatency.list_flags(),{name = "bla", reason="blabla"}) end, },
    { "for-loop",  function()
          for i, flg in ipairs(ulatency.list_flags()) do
            if flg.name == "bla" and flg.reason=="blabla" then break end
          end
        end }  
  )
  ulatency.clear_flag_source()

  -- proc flags
  proc = ulatency.get_pid(1)
  for _,flag in ipairs(flags) do
    proc:add_flag(flag)
  end
  function check_label(labels, proc) --copied from scheduler.lua
  for j, flag in pairs(proc:list_flags(true)) do
    for k, slabel in pairs(labels) do
      if flag.name == slabel then
        return true
      end
    end
  end
  end
  local labels = {"user.poison.session", "bla"}
  benchmark("simple proc labels check",  1e5,
    { "ulatency.match_flag", function() ulatency.match_flag(labels, proc) end },
    { "check_label", function() check_label(labels, proc) end, }
  )
  ulatency.clear_flag_source(proc)
end


function test_function_parameters()
  local function empty() end
  local nothing = false
  benchmark("function with params vs no params", 1e5,
    { "function with two tostring params", function() empty(tostring(23), tostring(53)) end },
    { "function with two numeric params", function() empty(23, 53) end },
    { "function without params", function() empty() end },
    { "false condition", function() if nothing then end end }
  )
end
