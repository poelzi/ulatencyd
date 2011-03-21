#include "config.h"
#include "ulatency.h"

#include <glib.h>
#include <glib-object.h>

#include <dbus/dbus.h>
#include <dbus/dbus-glib.h>
#include <dbus/dbus-glib-bindings.h>
#include <dbus/dbus-glib-lowlevel.h>
#include <polkit/polkit.h>

#define DMAX 5000

static void
check_authorization_cb (PolkitAuthority *authority,
                        GAsyncResult    *res,
                        gpointer         user_data)
{
  struct callback_data *data = user_data;
  PolkitAuthorizationResult *result;
  GError *error;

  error = NULL;
  result = polkit_authority_check_authorization_finish (authority, res, &error);
  if (error != NULL) {
      g_warning("Error checking authorization: %s\n", error->message);
      g_error_free (error);
      DBusMessage *ret = dbus_message_new_method_return(data->message);
      dbus_connection_send(data->connection, ret, NULL);
      dbus_message_unref(ret);
  } else {
      const gchar *result_str;
      if (polkit_authorization_result_get_is_authorized (result)) {
          g_debug("Authorization result: authorized");
          data->callback(data);
      } else {
          if (polkit_authorization_result_get_is_challenge (result))
               result_str = "challenge";
          else
               result_str = "not authorized";
          g_debug ("Authorization result: %s\n", result_str);
      }
      DBusMessage *ret = dbus_message_new_method_return(data->message);
      dbus_connection_send(data->connection, ret, NULL);
      dbus_message_unref(ret);
  }
  dbus_connection_unref(data->connection);
  dbus_message_unref(data->message);
}

static gboolean
do_cancel (GCancellable *cancellable)
{
  g_print ("Timer has expired; cancelling authorization check\n");
  g_cancellable_cancel (cancellable);
  return FALSE;
}


int check_polkit(const char *methode,
             DBusConnection *connection,
             DBusMessage *message,
             char *action_id,
             void (*callback)(struct callback_data *data),
             void *user_data,
             int allow_user_interaction,
             u_proc *proc, char *config) {
    PolkitSubject *subject;
    PolkitDetails *details;
    PolkitCheckAuthorizationFlags flags;
    gchar tmp[DMAX+1];
    

    /* Set details - see polkit-action-lookup.c for where
     * these key/value pairs are used
     */
    printf("a\n");
    details = polkit_details_new ();
    if (proc != NULL)
      {
        g_snprintf(&tmp[0], DMAX, "%d", proc->pid);
        polkit_details_insert (details, "pid", &tmp[0]);
        g_snprintf(&tmp[0], DMAX, "%d", proc->proc.ppid);
        polkit_details_insert (details, "ppid", &tmp[0]);
        g_snprintf(&tmp[0], DMAX, "%d", proc->proc.tpgid);
        polkit_details_insert (details, "gid", &tmp[0]);
        g_snprintf(&tmp[0], DMAX, "%d", proc->proc.pgrp);
        polkit_details_insert (details, "pgrp", &tmp[0]);
        g_snprintf(&tmp[0], DMAX, "%d", proc->proc.session);
        polkit_details_insert (details, "session", &tmp[0]);

      }
    if(config) {
        polkit_details_insert (details, "config", config);
    }

    subject = polkit_system_bus_name_new (dbus_message_get_sender (message));
    //subject = polkit_unix_process_new (getpid());

    struct callback_data *data = g_malloc0(sizeof(struct callback_data));
    data->cancellable = g_cancellable_new ();
    dbus_connection_ref(connection);
    data->connection = connection;
    dbus_message_ref(message);
    data->message = message;
    data->user_data = user_data;
    data->callback = callback;

    flags = POLKIT_CHECK_AUTHORIZATION_FLAGS_NONE;
    if (allow_user_interaction)
      flags |= POLKIT_CHECK_AUTHORIZATION_FLAGS_ALLOW_USER_INTERACTION;

    g_debug("check authorization via polkit");
    //g_timeout_add (10 * 1000,
    //             (GSourceFunc) do_cancel,
    //             data->cancellable);


    polkit_authority_check_authorization (U_polkit_authority,
                                          subject,
                                          action_id,
                                          details,
                                          flags,
                                          data->cancellable,
                                          (GAsyncReadyCallback) check_authorization_cb,
                                          data);

    g_object_unref (subject);
    g_object_unref (details);
    return TRUE;
}
