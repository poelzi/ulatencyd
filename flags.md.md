# Flag system

Processes are usually scheduled according their attached flags. Flags must contain a name and can optionally have some other values attached to it. The name can be any asciinumeric string, please don't use non ascii based strings as lua does not have the knowledge of unicode. The name is based on convention, having a top level category and subcategories separated by `.`, like `user.ui`, `user.media`,...

A flags once added stays until the process dies, flag got removed or the optional timeout hits.

Possible values are:

    char          *name;         // label name
    char          *reason;       // why the flag was set. This makes most sense with emergency flags
    time_t         timeout;       // timeout when the flag will disapear
    int32_t        priority;      // custom data: priority
    int64_t        value;         // custom data: value
    int64_t        threshold;     // custom data: threshold
    uint32_t       inherit : 1;      // will apply to all children


## user.
Indicates a typical user process

- **user.ui** - graphical user interface
- **user.media** - media players
- **user.bg_high** - very important background process for the user
- **user.idle** - process that is not necessary and will only get spare resources.

- **user.poison** - process that causes trouble to the user & system. Depending on _reason_
  - _reason="memory"_ - using a lot of ram in memory pressure situation
- **user.poison.group** - belongs to a group of process that cause trouble
  - _reason="memory"_ - using a lot of ram in memory pressure situation

## system.
System important processes

* **system.essential** - very essential system processes like X, wayland,...

## daemon.
System daemon processes, that run in background

- **daemon.idle** - absolutely lowest priority of all 
- **daemon.bg** - a little bit more important then idle, but no important processes.

## sched.
Special scheduling required

- **sched.rt** - process must be in realtime group
