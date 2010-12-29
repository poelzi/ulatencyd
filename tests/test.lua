-- adjust package.path
package.path = package.path .. ";tests/?.lua"

function to_string(data, indent)
    local str = ""

    if(indent == nil) then
        indent = 0
    end

    -- Check the type
    if(type(data) == "string") then
        str = str .. (" "):rep(indent) .. data .. "\n"
    elseif(type(data) == "number") then
        str = str .. (" "):rep(indent) .. data .. "\n"
    elseif(type(data) == "boolean") then
        if(data == true) then
            str = str .. "true"
        else
            str = str .. "false"
        end
    elseif(type(data) == "table") then
        local i, v
        for i, v in pairs(data) do
            -- Check for a table in a table
            if(type(v) == "table") then
                str = str .. (" "):rep(indent) .. i .. ":\n"
                str = str .. to_string(v, indent + 2)
            else
                str = str .. (" "):rep(indent) .. i .. ": " .. to_string(v, 0)
            end
        end
    else
        return tostring(data).."\n"
    end

    return str
end

function pprint(data)
  print(to_string(data))
end

U_PROC_META = debug.getregistry()["U_PROC_META"]
U_FLAG_META = debug.getregistry()["U_FLAG_META"]

function assert_u_proc(data)
  return assert_userdata(data, "Not a u_proc object") or 
         assert_metatable(U_PROC_META, data, "Not a u_proc object")
end

function assert_u_flag(data)
  return assert_userdata(data, "Not a u_flag object") or 
         assert_metatable(U_FLAG_META, data, "Not a u_flag object")
end


function assert_cmp_table(exp, val, err)
  if #exp ~= #val then
    assert_equal(exp, val, 0, "not same length")
  end
  for k, v in ipairs(exp) do
    assert_equal(v, val[k], "value in table differs")
  end
end

arg = {}

require('tests.lunatest')

suites = {"misc", "processes", "filter"}

loaded_suites = lunatest.get_suites()

current_id = 1
current_suite = suites[current_id]


function run_suite(bla)
  if loaded_suites[current_suite] then
    if loaded_suites[current_suite].done and loaded_suites[current_suite].done() then
      current_id = current_id + 1
      current_suite = suites[current_id]
    else
      return true
    end
  end
  lunatest.suite(current_suite)
  lunatest.run(nil, current_suite)
end

ulatency.add_timeout(run_suite, 500)


--ulatency.quit_daemon()
ulatency.add_timeout(ulatency.quit_daemon, 100000)


