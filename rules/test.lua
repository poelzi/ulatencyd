flag = ulatency.new_flag{name="test", reason="dbus"}
ulatency.add_flag(flag)
flag = ulatency.new_flag{name="test", reason="need more data", value=32, threshold=666}
ulatency.add_flag(flag)