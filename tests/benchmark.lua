-- adjust package.path
package.path = package.path .. ";tests/benchmarks/?.lua"

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

function benchmark(name, count, ...)
  local times, descs = {}, {}
  for _, bench in ipairs({...}) do
    descs[#descs+1] = bench[1]
    local func = bench[2]
    local t=os.clock()
    for i=1,count do 
      func()
    end
    times[#times+1] = os.clock() - t
  end
  output = {}
  for i=2,#times do
    output[#output+1] = string.format("%d%% time of %s", times[1]/times[i]*100, descs[i])
  end
  print(string.format("BENCHMARK (%s): %s takes %s", name, descs[1], table.concat(output, ' and ')))
end


arg = {}

require('tests.lunatest')

suites = {"misc"}

loaded_suites = lunatest.get_suites()

current_id = 0
current_suite = suites[current_id]


function run_suite(bla)
  while true do
    if loaded_suites[current_suite] then
      if loaded_suites[current_suite].test_done then
        if not loaded_suites[current_suite].test_done() then
          return true
        end
      end
    end
    current_id = current_id + 1
    current_suite = suites[current_id]
    if not current_suite then
      print("all lua benchmarks done")
      ulatency.fallback_quit()
      return false
    end
    lunatest.suite(current_suite)
    loaded_suites = lunatest.get_suites()
    lunatest.run(nil, current_suite)
    if loaded_suites[current_suite].test_done then
      return true
    end
  end
end

ulatency.add_timeout(run_suite, 500)


--ulatency.quit_daemon()
ulatency.add_timeout(ulatency.fallback_quit, 100000)


