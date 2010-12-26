module(..., package.seeall)

function test_list_pids() 
  pids = ulatency.list_pids()

  assert_true(#pids > 10, "very likely")

  for k,v in pairs(pids) do
    assert_number(k, "key not number")
    assert_number(v, "pid not number")
    assert_true(v > 0, "pid not > 0")
  end

end

function test_get_pid() 
  pid = ulatency.get_pid(1)
  
  print("pid", pid)

  assert_equal(1, pid.pid)
  assert_equal(true, pid.is_valid)

end



function test_ok()
   assert_true(true)
end