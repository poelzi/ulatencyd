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
        print_debug(1, "Error: unknown data type: %s", type(data))
    end

    return str
end

function pprint(data)
  print(to_string(data))
end

U_PROC_META = debug.getregistry()["U_PROC"]

function assert_u_proc(data)
  return assert_userdata(data, "Not a u_proc object") or 
         true
         -- FIXME
         --assert_metatable(U_PROC_META, data, "Not a u_proc object")
end

arg = {}

require('tests.lunatest')

lunatest.suite("test1")
lunatest.suite("processes")


lunatest.run()
ulatency.quit_daemon()

