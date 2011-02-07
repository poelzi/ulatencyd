ulatencyd has 3 different parts:

* core, which does process parsing, building a process tree, etc
* rules, which categorize the processes, analyze the system etc
* the scheduler, which uses the information collected by the core and rules to make decisions on the processes

Some settings are adjustable in `/etc/ulatencyd/ulatencyd.conf` and the cgroups that will be used can be changed 
in `/etc/ulatencyd/cgroups.conf`

The core listens on the kernel when new processes are spawned or exit and runs the rules an scheduler on them.
Additionally, a full iteration is run every 10 seconds on all processes. This is required for example when flags, 
set on a process expire and the scheduler will make another decision.

The rules and the scheduler can be adjusted by the user to his wishes.

* [Writing rules](Writing-Rules)
* [Adjusting the default scheduler](Adjusting-default-scheduler)