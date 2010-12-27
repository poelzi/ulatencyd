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


function test_ok()
   assert_true(true)
end