module(..., package.seeall)

test_active_done = false

function test_active()
  TEST_PIDS = {23, 43, 53, 1231, 23, 743, 235, 23}
  RV = {}
  RV[1] = {23}
  RV[2] = {43, 23}
  RV[3] = {53, 43, 23}
  RV[4] = {1231, 53, 43, 23}
  RV[5] = {23, 1231, 53, 43}
  RV[6] = {743, 23, 1231, 53, 43}
  RV[7] = {235, 743, 23, 1231, 53}
  RV[8] = {23, 235, 743, 1231, 53}

  TEST_I = 1

  function add_active()
    ulatency.set_active_pid(1, TEST_PIDS[TEST_I])
    assert_cmp_table(RV[TEST_I], ulatency.get_active_pids(1))
    TEST_I = TEST_I + 1
    if TEST_I > #TEST_PIDS then
      test_active_done = true
      return false
    end
    return true
  end

  ulatency.add_timeout(add_active, 1000)
end

function done()
  return test_active_done
end