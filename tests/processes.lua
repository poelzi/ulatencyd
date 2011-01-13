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

  assert_true(pid:get_n_children() > 1, "init should have more then 1 children")

  local childs = pid:get_children()

  assert_equal(pid:get_n_children(), #childs, "size of get_n_children differs")

  for k,v in pairs(childs) do
    assert_u_proc(v)
  end


end

function test_flag_inherence() 
  pid = ulatency.get_pid(1)

  local flag_in = ulatency.new_flag{name = "inher", inherit = true}
  local flag_non = ulatency.new_flag{name = "loc", inherit = false}
  
  pid:add_flag(flag_in)
  pid:add_flag(flag_non)

  local childs = pid:get_children()

  assert_cmp_table({flag_non, flag_in}, pid:list_flags())

  local exp_child = {flag_in}

  for k,v in pairs(childs) do
    assert_u_proc(v)
    assert_cmp_table(exp_child, v:list_flags(true))
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
  assert_equal("test", flag.name)
  flag.name = "blubb"
  assert_equal("blubb", flag.name)
  assert_equal(false, flag.inherit, "inherit")
  assert_equal(0, flag.priority, "priority")
  assert_equal(0, flag.timeout, "timeout")
  assert_equal(nil, flag.reason, "reason")
  assert_equal(0, flag.value, "value")
  assert_equal(0, flag.threshold, "threshold")
  flag.reason = "bla"
  assert_equal("bla", flag.reason, "reason test")
  flag.value = -21823
  assert_equal(-21823, flag.value)
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

  -- test with table init
  local flag3 = ulatency.new_flag{name = "huhu", 
                                  inherit = 1, 
                                  priority = 64,
                                  value = 23,
                                  threshold = 443,
                                  timeout = 55,
                                  reason = 2,
                                  nonsense = 22345}
  assert_equal("huhu", flag3.name, "name")
  assert_equal(true, flag3.inherit)
  assert_equal(64, flag3.priority)
  assert_equal(55, flag3.timeout)
  assert_equal("2", flag3.reason)
  assert_equal(23, flag3.value)
  assert_equal(443, flag3.threshold)
  assert_equal(nil, flag3.nonsense)

end


