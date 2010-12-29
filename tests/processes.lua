module(..., package.seeall)

function test_list_pids() 
  pids = ulatency.list_pids()

  assert_true(#pids > 10, "very unlikely that less then 10 processes exist")

  for k,v in pairs(pids) do
    assert_number(k, "key not number")
    assert_number(v, "pid not number")
    assert_true(v > 0, "pid not > 0")
  end

end

function test_get_pid() 
  pid = ulatency.get_pid(1)

  assert_equal(1, pid.pid)
  assert_equal(true, pid.is_valid)
  
  for k,v in pairs(pid:get_children()) do
    assert_u_proc(v)
  end
  
end

function test_list_processes() 
  procs = ulatency.list_processes()

  assert_true(#procs > 10, "very unlikely that less then 10 processes exist")

  for k,v in pairs(procs) do
    assert_userdata(v, "Not a userdata")
    assert_u_proc(v)
    -- FIXME
    --assert_metatable(ulatency, v, "Not metatable U_PROC")
    assert_number(k, "key not a number")
    
    -- except for the root process very one must have a parent
    local parent = v:get_parent()
    --print("pid", v.pid)
    --print("parent:", parent)

    if(v.ppid == 0) then
      assert_nil(v:get_parent(), "Parent of pid " .. tostring(v.pid) .. " is not nil")
    else
      assert_u_proc(parent)
    end
  end

end

function test_new_flag() 
  local flag = ulatency.new_flag("test")
  assert_u_flag(flag)
  assert_equal(flag.name, "test")
  flag.name = "blubb"
  assert_equal(flag.name, "blubb")
  assert_equal(flag.priority, 0)
  assert_equal(flag.timeout, 0)
  assert_equal(flag.reason, 0)
  assert_equal(flag.value, 0)
  assert_equal(flag.threshold, 0)
  flag.reason = ulatency.REASON_MEMORY
  assert_equal(flag.reason, ulatency.REASON_MEMORY)
  flag.value = -21823
  assert_equal(flag.value, -21823)

  local pid = ulatency.get_pid(1)
  pid:add_flag(flag)
  pid:add_flag(flag)
  pid:add_flag(flag)
  pprint(pid:list_flags())
  assert_len(1, pid:list_flags(), "to much flags on proc")
  
  local flag2 = ulatency.new_flag("haha")
  pid:add_flag(flag2)
  pprint(pid:list_flags())
  assert_len(2, pid:list_flags(), "to much flags on proc")
  
  pid:del_flag(flag2)
  pprint(pid:list_flags())
  assert_len(1, pid:list_flags(), "to much flags on proc")

  flag2.name = "haha"
  pid:add_flag(flag2)
  pid:clear_flag_name("haha")
  assert_len(1, pid:list_flags(), "to much flags on proc")

  pid:clear_flag_source()
  assert_len(0, pid:list_flags(), "source clear failed")

  pid:add_flag(flag2)
  pid:add_flag(flag)
  pid:clear_flag_all()
  assert_len(0, pid:list_flags(), "all clear failed")

end


