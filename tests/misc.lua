module(..., package.seeall)

test_active_done = false

function test_active()
  TEST_PIDS = {23, 43, 53, 1231, 23, 743, 235, 23}
  RV = {}
  RV[1] = {{pid=23}}
  RV[2] = {{pid=43}  , {pid=23}}
  RV[3] = {{pid=53}  , {pid=43}  , {pid=23}}
  RV[4] = {{pid=1231}, {pid=53}  , {pid=43}  , {pid=23}}
  RV[5] = {{pid=23}  , {pid=1231}, {pid=53}  , {pid=43}}
  RV[6] = {{pid=743} , {pid=23}  , {pid=1231}, {pid=53}  , {pid=43}}
  RV[7] = {{pid=235} , {pid=743} , {pid=23}  , {pid=1231}, {pid=53}}
  RV[8] = {{pid=23}  , {pid=235} , {pid=743} , {pid=1231}, {pid=53}}

  TEST_I = 1

  function add_active()
    print("test active list ["..tostring(TEST_I).."/8]")
    ulatency.set_active_pid(1, TEST_PIDS[TEST_I])
    assert_cmp_table(RV[TEST_I], ulatency.get_active_pids(1), nil, {last_change=true})
    TEST_I = TEST_I + 1
    if TEST_I > #TEST_PIDS then
      test_active_done = true
      return false
    end
    return true
  end

  ulatency.add_timeout(add_active, 1000)
end

function test_done()
  return test_active_done
end