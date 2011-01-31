# Start Hacking

* Checkout trunk
* `cmake .`
* `ccmake .` and change DEVELOP_MODE to True. This allows you to develop in your checkout without having to install it
  all the time. This changes the behavoir slightly:
  * ulatencyd will not register a system dbus name, but will use the session bus. He still connects to the system bus, too.
* run `make DEBUG=1` or `make DEBUG=1 VERBOSE=1`