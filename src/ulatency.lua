-- this file is for documentation purpuses only
--! @file ulatency.lua
--! This file documents the 'ulatency' table which is implemented in the core
--!



--! @brief u_proc class
u_proc = {}

--! @brief parent of process
--! @return u_proc instance or nil
function u_proc:get_parent()
end


ulatency = {}

ulatency.version="VERSION"
ulatency.release_agent = "/PATH/TO/RELEASEAGENT"
ulatency.path_rules_directory = "/PATH/TO/RULES"
ulatency.path_config_directory = "/PATH/TO/CONFIG"

ulatency.smp_num_cpus = 23

  // glib log level
ulatency.LOG_LEVEL_ERROR =  G_LOG_LEVEL_ERROR
ulatency.LOG_LEVEL_CRITICAL = G_LOG_LEVEL_CRITICAL
ulatency.LOG_LEVEL_WARNING = G_LOG_LEVEL_WARNING
ulatency.LOG_LEVEL_MESSAGE = G_LOG_LEVEL_MESSAGE
ulatency.LOG_LEVEL_INFO = G_LOG_LEVEL_INFO
ulatency.LOG_LEVEL_DEBUG = G_LOG_LEVEL_DEBUG
ulatency.LOG_LEVEL_SCHED = U_LOG_LEVEL_SCHED
ulatency.LOG_LEVEL_TRACE = U_LOG_LEVEL_TRACE
  
ulatency.FILTER_STOP = FILTER_STOP
ulatency.FILTER_SKIP_CHILD = FILTER_SKIP_CHILD

ulatency.IOPRIO_CLASS_NONE = IOPRIO_CLASS_NONE
ulatency.IOPRIO_CLASS_RT = IOPRIO_CLASS_RT
ulatency.IOPRIO_CLASS_BE = IOPRIO_CLASS_BE
ulatency.IOPRIO_CLASS_IDLE = IOPRIO_CLASS_IDLE

  // realtime priority stuff
ulatency.SCHED_OTHER = SCHED_OTHER
ulatency.SCHED_FIFO = SCHED_FIFO
ulatency.SCHED_RR = SCHED_RR
ulatency.SCHED_BATCH = SCHED_BATCH
ulatency.SCHED_IDLE = SCHED_IDLE

ulatency.UPROC_NEW = UPROC_NEW
ulatency.UPROC_INVALID = UPROC_INVALID
ulatency.UPROC_ALIVE = UPROC_ALIVE

