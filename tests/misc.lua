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

function test_sysflags()
  flag = ulatency.new_flag{name="hello"}
  ulatency.add_flag(flag)
  assert_len(1, ulatency.list_flags(), "len of system flags not right")
  flag2 = ulatency.new_flag{name="hello2", reason="2"}
  ulatency.add_flag(flag)
  assert_len(1, ulatency.list_flags(), "len of system flags not right")
  ulatency.add_flag(flag2)
  assert_len(2, ulatency.list_flags(), "len of system flags not right")
  ulatency.del_flag(flag2)
  assert_len(1, ulatency.list_flags(), "len of system flags not right")
  ulatency.clear_flag_source()
  assert_len(0, ulatency.list_flags(), "len of system flags not right")
  ulatency.add_flag(flag)
  ulatency.clear_flag_name("hello")
  assert_len(0, ulatency.list_flags(), "len of system flags not right")
end

function test_find_flags()
  flag = ulatency.new_flag{name="hello"}
  flag2 = ulatency.new_flag{name="hello2"}
  flag3 = ulatency.new_flag{name="bla", value=3}
  flag4 = ulatency.new_flag{name="bla", threshold=4}

  all = {flag4, flag3, flag2, flag}
  assert_equal(nil, ulatency.find_flag(all, {name = "user.poison.session"}), "user.poision not in list")
  assert_equal(flag, ulatency.find_flag(all, {name = "hello"}), "hello in list")
  assert_equal(flag2, ulatency.find_flag(all, {name = "hello2"}), "hello in list")
  assert_equal(nil, ulatency.find_flag(all, {name = "hello2", value = 32}), "hello2 value not in list")
  assert_equal(flag3, ulatency.find_flag(all, {name = "bla", value = 3}), "bla value in list")
  assert_equal(nil, ulatency.find_flag(all, {name = "bla", value = 4}), "bla value 4 not in list")
  assert_equal(flag4, ulatency.find_flag(all, {name = "bla", threshold = 4}), "bla value 4 in list")

end

function test_done()
  return test_active_done
end
