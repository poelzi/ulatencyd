module(..., package.seeall)

require("posix")

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

function test_cgroups_list()
  if posix.access("/proc/cgroups") == 0 then
    grps = ulatency.get_cgroup_subsystems()
    assert_true(#grps > 0, "cgroups subsystems empty")
  end
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

function test_match_flag()
  local flags = {
    ulatency.new_flag{name="hello"},
    ulatency.new_flag{name="hello2"},
    ulatency.new_flag{name="bla", value=3},
    ulatency.new_flag{name="bla", threshold=4, reason="blabla"},
  }
  local function test_flags(desc, where)
    assert_equal(false,ulatency.match_flag({name = "user.poison.session"}, where), desc..": name=user.poision not in list")
    assert_equal(false,ulatency.match_flag({{name = "user.poison.session"}, "hello3"}, where), desc..": name=user.poision nor hello3 in list")
    assert_equal(true,ulatency.match_flag({name = "hello"}, where), desc..": name=hello in list")
    assert_equal(true,ulatency.match_flag({"hello"}, where), desc..": hello in list")
    assert_equal(true,ulatency.match_flag({"user.poison.session", "hello"}, where), desc..": user.poison.session or hello in list")
    assert_equal(false,ulatency.match_flag({name = "hello2", value = 32}, where), desc..": name=hello2 value not in list")
    assert_equal(false,ulatency.match_flag({value = 32, name = "hello2"}, where), desc..": name=hello2 value not in list")
    assert_equal(true,ulatency.match_flag({{name = "hello2", value = 32},"hello"}, where), desc..": name=hello2 value or hello in list")
    assert_equal(true,ulatency.match_flag({{name = "hello2", value = 32},{name = "hello"}}, where), desc..": name=hello2 value or name=hello in list")
    assert_equal(true,ulatency.match_flag({{name = "hello2", value = 32},{name = "bla", reason="blabla"}}, where), desc..": name=hello2 value or name=bla reason in list")
    assert_equal(true,ulatency.match_flag({"hello2",{name = "bla", reason="blabla"}}, where), desc..": hello2 or name=bla reason in list")
  end

  -- flags list
  test_flags('flags list', flags)

  -- system flags
  for _,flag in ipairs(flags) do
    ulatency.add_flag(flag)
  end
  test_flags('system flags')
  ulatency.clear_flag_source()

  -- proc flags
  proc = ulatency.get_pid(1)
  for _,flag in ipairs(flags) do
    proc:add_flag(flag)
  end
  test_flags('proc flags', proc)
  ulatency.clear_flag_source(proc)
end

function test_sysctl()
  assert_true(ulatency.get_sysctl("kernel.version"), "kernel.version not existing")
  assert_false(ulatency.set_sysctl("kernel.version", "bla"), "kernel.version should not be writeable")
end

function test_get_sessions()
  sessions = ulatency.get_sessions()
  assert_true(#sessions > 0, "very unlikely that no session exists")

  found_active = false
  for k,v in pairs(sessions) do
    assert_u_session(v)
    assert_number(k, "key not a number")
    assert_true(v.id >= ulatency.USESSION_USER_FIRST, "non user sessions can't be in U_SESSION list")
    assert_boolean(v.is_active)
    if v.is_active then
      assert_false(found_active, "only one active session allowed")
      found_active = true
    end
  end
  assert_true(found_active, "unlikely no session is active")

  init = ulatency.get_pid(1)
  assert_true (init.session == nil, "init should not be in user session")
  assert_true (init.session_id == ulatency.USESSION_INIT)
end


function test_done()
  return test_active_done
end
