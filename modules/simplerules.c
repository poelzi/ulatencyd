/*
    Copyright 2011 Daniel Poelzleithner <ulatencyd at poelzi dot org>

    This file is part of ulatencyd.

    ulatencyd is free software: you can redistribute it and/or modify it under 
    the terms of the GNU General Public License as published by the 
    Free Software Foundation, either version 3 of the License, 
    or (at your option) any later version.

    ulatencyd is distributed in the hope that it will be useful, 
    but WITHOUT ANY WARRANTY; without even the implied warranty of 
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
    See the GNU General Public License for more details.

    You should have received a copy of the GNU General Public License 
    along with ulatencyd. If not, see http://www.gnu.org/licenses/.
*/
#define _GNU_SOURCE


#ifndef G_LOG_DOMAIN
#define G_LOG_DOMAIN "simplerules"
#endif

#include "config.h"
#include "ulatency.h"
#include <err.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <glib.h>
#include <sys/stat.h>
#include <fnmatch.h>

int simplerules_id;
int simplerules_debug;

struct simple_rule {
  gid_t         gid;
  uid_t         uid;
/*  char          *cmdline;
  char          *exe;
  char          *basename;
*/
  char          *pattern;
  GPatternSpec  *glob_exe;
  GPatternSpec  *glob_basename;
  GPatternSpec  *glob_cmd;
  GRegex        *re_exe;
  GRegex        *re_cmd;
  GRegex        *re_basename;
  u_flag        *template;
};


struct filter_data {
    GList *rules;
};

struct filter_data FILTERS[] = {
    {NULL},
    {NULL},
    {NULL},
};

enum {
    LIST_FAST,
    LIST_NORMAL,
    LIST_END
};

#define simple_debug(...) \
    if(simplerules_debug) g_debug(__VA_ARGS__);

int parse_line(char *line, int lineno) {
    char **chunks = NULL;
    GError *error = NULL;
    gint chunk_len;
    struct simple_rule *rule = NULL;
    int i, instant=0;
    char *value, *key;
    int tmp;


    if(line[0] == '#')
        return TRUE;
    if(strlen(line) == 0)
        return TRUE;

    g_shell_parse_argv(line, 
                       &chunk_len,
                       &chunks,
                       &error);
    if(error) {
        g_warning("can't parse line %d: %s", lineno, error->message);
        goto error;
    }

    if(chunk_len && chunk_len < 2) {
        g_warning("not enough arguments in line %d: %s", lineno, line);
        goto error;
    }

    rule = g_slice_new0(struct simple_rule);

    if(chunks[0][0] == '/') {
        rule->glob_exe = g_pattern_spec_new(chunks[0]);

    } else if(!strncmp(chunks[0], "cmd:", 4)) {
        rule->glob_cmd = g_pattern_spec_new(chunks[0]+4);

    } else if(!strncmp(chunks[0], "re_exe:", 7)) {
        rule->re_exe = g_regex_new(chunks[0] + 7, G_REGEX_OPTIMIZE, 0, &error);
        if(error && error->code) {
            g_warning("Error compiling regular expression in %s: %s", chunks[0], error->message);
            goto error;
        }
    } else if(!strncmp(chunks[0], "re_cmd:", 7)) {
        rule->re_cmd = g_regex_new(chunks[0] + 7, G_REGEX_OPTIMIZE, 0, &error);
        if(error && error->code) {
            g_warning("Error compiling regular expression in %s: %s", chunks[0], error->message);
            goto error;
        }
    } else if(!strncmp(chunks[0], "re_base:", 8)) {
        rule->re_cmd = g_regex_new(chunks[0] + 7, G_REGEX_OPTIMIZE, 0, &error);
        if(error && error->code) {
            g_warning("Error compiling regular expression in %s: %s", chunks[0], error->message);
            goto error;
        }
    } else {
        rule->glob_basename = g_pattern_spec_new(chunks[0]);
    }
    rule->pattern = g_strdup(chunks[0]);
    rule->template = g_slice_new0(u_flag);
    rule->template->name = g_strdup(chunks[1]);

    for(i = 2; chunks[i]; i++) {
        key = chunks[i];
        value = strstr(chunks[i], "=");

        if(!value) {
            g_error("invalid argument in line %d: '=' missing", lineno);
            goto error;
        }
        // split by replacing = with null byte
        *value = 0;
        value++;

        if(strcmp(key, "reason") == 0) {
            rule->template->reason = g_strdup(value);
        } else if(strcmp(key, "timeout") == 0) {
            rule->template->timeout = (time_t)atoll(value);
        } else if(strcmp(key, "priority") == 0) {
            rule->template->priority = (int32_t)atoi(value);
        } else if(strcmp(key, "value") == 0) {
            rule->template->value = (int64_t)atoll(value);
        } else if(strcmp(key, "threshold") == 0) {
            rule->template->threshold = (int64_t)atoll(value);
        } else if(strcmp(key, "inherit") == 0) {
            tmp = atoi(value);
            rule->template->inherit = tmp;
        } else if(strcmp(key, "instant") == 0) {
            instant = !strcmp(value, "true") || atoi(value);
        }
    }

    if(instant)
        FILTERS[LIST_FAST].rules = g_list_append(FILTERS[LIST_FAST].rules, rule);
    else
        FILTERS[LIST_NORMAL].rules = g_list_append(FILTERS[LIST_NORMAL].rules, rule);

    g_strfreev(chunks);
    return TRUE;
error:
    g_strfreev(chunks);
    g_slice_free(struct simple_rule, rule);
    g_error_free(error);
    return FALSE;

}


int load_simple_file(const char *path) {
    char *content, **lines, *line;
    gsize length;
    int i;
    GError *error = NULL;

    if(!g_file_get_contents(path,
                            &content,
                            &length,
                            &error)) {
        g_warning("can't load simple rule file %s: %s", path, error->message);
        return FALSE;
    }

    g_debug("load simple rule file: %s", path);

    lines = g_strsplit_set(content, "\n", -1);
    for(i = 0; lines[i]; i++) {
        line = lines[i];

        parse_line(line, i+1);

    }
    g_strfreev(lines);
    g_free(content);

    return TRUE;
}


int load_simple_directory(char *path) {
    char rpath[PATH_MAX+1];
    gsize  disabled_len;
    int i, j;
    char **disabled;
    char *rule_name = NULL;
    struct stat sb;

    disabled = g_key_file_get_string_list(config_data, "simplerules",
                                          "disabled_rules", &disabled_len, NULL);


    g_message("load simple rules directory: %s", path);


    struct dirent **namelist;
    int n;

    n = scandir(path, &namelist, 0, versionsort);
    if (n < 0) {
       g_warning("cant't load directory %s", path);
       g_strfreev(disabled);
       return FALSE;
    } else {
       for(i = 0; i < n; i++) {

          if(fnmatch("*.conf", namelist[i]->d_name, 0)) {
            free(namelist[i]);
            continue;
          }
          rule_name = g_strndup(namelist[i]->d_name,strlen(namelist[i]->d_name)-4);

          for(j = 0; j < disabled_len; j++) {
            if(!g_ascii_strcasecmp(disabled[j], rule_name))
              goto skip;
          }

          snprintf(rpath, PATH_MAX, "%s/%s", path, namelist[i]->d_name);
          if (stat(rpath, &sb) == -1)
              goto skip;
          if((sb.st_mode & S_IFMT) != S_IFREG)
              goto next;

          load_simple_file(rpath);

      next:
          g_free(rule_name);
          rule_name = NULL;

          free(namelist[i]);
          continue;
      skip:
          g_debug("skip rule: %s", namelist[i]->d_name);
          g_free(rule_name);
          rule_name = NULL;

          free(namelist[i]);
       }
       free(namelist);
    }
    g_strfreev(disabled);
    return TRUE;
}

void read_rules(void) {
    load_simple_directory(QUOTEME(CONFIG_PATH)"/simple.d");
    load_simple_file(QUOTEME(CONFIG_PATH)"/simple.conf");

    return;
}

int rule_applies(u_proc *proc, struct simple_rule *rule) {
//    u_proc_ensure(proc, EXE, TRUE);
//    printf("add proc %d to %s\n", proc->pid, proc->exe);
    gboolean match = FALSE;
    if(rule->glob_cmd) {
        if(u_proc_ensure(proc, CMDLINE, NOUPDATE) && proc->cmdline_match) {
           match = g_pattern_match_string(rule->glob_cmd, proc->cmdline_match);
           simple_debug("match pid:%d cmdline glob:'%s' cmdline:'%s' = %d", proc->pid, rule->pattern, proc->cmdline_match, match)
           if(match)
              return TRUE;
        }
    }
    if(rule->glob_basename) {
        if(u_proc_ensure(proc, CMDLINE, NOUPDATE) && proc->cmdfile) {
           match = g_pattern_match_string(rule->glob_basename, proc->cmdfile);
           simple_debug("match pid:%d basename glob:'%s' basename:'%s' = %d", proc->pid, rule->pattern, proc->cmdfile, match)
           if(match)
              return TRUE;
        }
    }
    if(rule->glob_exe) {
        if(u_proc_ensure(proc, EXE, NOUPDATE) && proc->exe) {
           match = g_pattern_match_string(rule->glob_exe, proc->exe);
           simple_debug("match pid:%d exe glob:'%s' exe:'%s' = %d", proc->pid, rule->pattern, proc->exe, match)
           if(match)
              return TRUE;
        }
    }
    if(rule->re_exe) {
        if(u_proc_ensure(proc, EXE, NOUPDATE) && proc->exe) {
           match = g_regex_match(rule->re_exe, proc->exe, 0, NULL);
           simple_debug("match pid:%d cmdline re:'%s' exe:'%s' = %d", proc->pid, rule->pattern, proc->cmdline_match, match)
           if(match)
              return TRUE;
        }
    }
    if(rule->re_cmd) {
        if(u_proc_ensure(proc, CMDLINE, NOUPDATE) && proc->cmdline) {
           match = g_regex_match(rule->re_cmd, proc->cmdline_match, 0, NULL);
           simple_debug("match pid:%d cmdline re:'%s' cmdline:'%s' = %d", proc->pid, rule->pattern, proc->cmdline_match, match)
           if(match)
              return TRUE;
        }
    }
    if(rule->re_basename) {
        if(u_proc_ensure(proc, CMDLINE, NOUPDATE) && proc->cmdfile) {
           match = g_regex_match(rule->re_basename, proc->cmdfile, 0, NULL);
           simple_debug("match pid:%d cmdline re:'%s' basename:'%s' = %d", proc->pid, rule->pattern, proc->cmdline_match, match)
           if(match)
              return TRUE;
        }
    }
    return FALSE;
}

void simple_add_flag(u_filter *filter, u_proc *proc, struct simple_rule *rule) {
    u_flag *t = rule->template;
    u_flag *nf = u_flag_new(filter, t->name);

    if(t->reason)
        nf->reason  = g_strdup(t->reason);
    if(t->timeout)
        nf->timeout = time(NULL) + t->timeout;
    nf->priority    = t->priority;
    nf->value       = t->value;
    nf->threshold   = t->threshold;
    nf->inherit     = t->inherit;
    if(t->urgent)
        nf->urgent = t->urgent;

    u_trace("add flag %s to %d", nf->name, proc->pid); 

    u_flag_add(proc, nf, -1);
    DEC_REF(nf);
}

int simplerules_run_proc(u_proc *proc, u_filter *filter) {
    GList *cur = ((struct filter_data *)filter->data)->rules;
    struct simple_rule *rule;

    while(cur) {
        rule = cur->data;

        if(rule_applies(proc, rule)) {
            simple_add_flag(filter, proc, rule);
        }
        cur = g_list_next(cur);
    }
    return FILTER_MIX(FILTER_RERUN_EXEC | FILTER_STOP, 0);
}


int simplerules_init() {
    int i = 0;
    simplerules_id = get_plugin_id();
    u_filter *filter;
    simplerules_debug = g_key_file_get_boolean(config_data, "simplerules", "debug", NULL);
//    target_rules = NULL;
    read_rules();
//    if(target_rules) {
    for(i=0; i < LIST_END; i++) {
        if(FILTERS[i].rules) {
            filter = filter_new();
            filter->type = FILTER_C;
            filter->name = g_strdup("simplerules");
            filter->callback = simplerules_run_proc;
            filter->data = &FILTERS[i];
            filter_register(filter, i == LIST_FAST);
        }
    }
//    }
    return 0;
}

