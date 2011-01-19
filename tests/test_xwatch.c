/*
    Copyright 2010,2011 ulatencyd developers

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

#define G_LOG_DOMAIN "test_xwatch"


#include "config.h"
#include "ulatency.h"

#define TEST_XWATCH

#include "../modules/xwatch.c"

DBusGConnection *U_dbus_connection;

int 
main ()
{
    /* Open the connection to the X server. Use the DISPLAY environment variable */

    struct x_server *xs;
    GList *cur;

    g_type_init ();

    GError *error = NULL;
    U_dbus_connection = dbus_g_bus_get (DBUS_BUS_SYSTEM,
                                 &error);
    if (U_dbus_connection == NULL)
      {
        g_warning("Failed to open connection to bus: %s\n",
                    error->message);
        g_error_free (error);
      }
  

    xwatch_init();

    add_all_console_kit(FALSE);
    add_all_console_kit(TRUE);
    add_all_console_kit(FALSE);

    /*
    xs = add_connection(1000, ":0");

    printf("xauth %p\n", xs->auth);
    
    printf("localhost: %s\n", localhost);

    printf ("\n");
    printf ("Informations of screen %ld:\n", xs->screen->root);
    printf ("  width.........: %d\n", xs->screen->width_in_pixels);
    printf ("  height........: %d\n", xs->screen->height_in_pixels);
    printf ("  white pixel...: %ld\n", xs->screen->white_pixel);
    printf ("  black pixel...: %ld\n", xs->screen->black_pixel);
    printf ("\n");


    printf ("current pid: %d\n", read_pid(xs));
    printf ("current pid: %d\n", read_pid(xs));
*/
    while(TRUE) {
      add_all_console_kit(TRUE);
      cur = server_list;
      printf("### run ### %d\n", g_list_length(server_list));
      while(cur) {
        printf ("current pid: %d\n", read_pid((struct x_server *)cur->data));
        cur = g_list_next(cur); 
      }
      sleep(1);
    }


/*  xcb_property_handlers_init 	(handle_prop,
		xcb_event_handlers_t *  	evenths	 
	) 
*/
/*
    cookie = xcb_get_any_property 	(connection,
		0,
		screen->root,
		"_NET_ACTIVE_WINDOW",
		100	 
	);
    prop = xcb_get_window_attributes_reply (connection,
                                              cookie, &error);
*/

/*  cookie2 = xcb_get_text_property 	(connection,
		screen->root,
		"_NET_ACTIVE_WINDOW"
	);
*/

    //xcb_event_handlers_init(connection, &doevent);
    //xcb_event_set_handler(&doevent, FOCUS_IN, handle_event, NULL);
    // static inline void xcb_event_set_##lkind##_handler(xcb_event_handlers_t *evenths, int (*handler)(void *, xcb_connection_t *, xcb_##lkind##_event_t *), void *data)
    //xcb_event_set_focus_in_handler(&doevent, handle_event, NULL);
    //  xcb_event_handlers_t *evenths, int (*handler)(void *, xcb_connection_t *, xcb_##lkind##_event_t *), void *data

    //xcb_event_wait_for_event_loop(&doevent);
/*    while(event = xcb_wait_for_event (connection)) {
      handle_event(event);
    }
*/
    return 0;
}
