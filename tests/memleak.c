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

#include <stdlib.h>

#include <stdio.h>
#include <getopt.h>
#include <string.h>

int
main (argc, argv)
     int argc;
     char **argv;
{
  int c = 0;
  int i = 0;
  int digit_optind = 0;
  int chunk = 1024;
  int nums = 10;
  int delay = 50000;
  char *tmp;


  while (1)
    {
      int this_option_optind = optind ? optind : 1;
      int option_index = 0;
      static struct option long_options[] =
      {
        {"chunk", 1, 0, 'c'},
        {"nums", 1, 0, 'n'},
        {"delay", 1, 0, 'd'},
        {"help", 0, 0, 'h'},
        {0, 0, 0, 0}
      };

      c = getopt_long (argc, argv, "n:c:hd:",
                   long_options, &option_index);
      if (c == -1)
    break;

      switch (c)
        {
        case 0:
          printf ("option %s", long_options[option_index].name);
          if (optarg)
            printf (" with arg %s", optarg);
          printf ("\n");
          break;

        case 'h':
          printf ("memleak:\n");
          printf ("-c size      size of chunk in kb\n");
          printf ("-n num       number of memory chunks\n");
          printf ("-d delay     delay in usecs between alloc \n");
          exit(0);
          break;

        case 'b':
          printf ("option b\n");
          break;

        case 'c':
          //printf ("option c with value '%s'\n", optarg);
          chunk = atoi(optarg);
          break;

        case 'n':
          nums = atoi(optarg);
          break;

        case 'd':
          delay = atoi(optarg);
          break;


        case '?':
          break;

        default:
          printf ("?? getopt returned character code 0%o ??\n", c);
        }
    }

  if (optind < argc)
    {
      printf ("non-option ARGV-elements: ");
      while (optind < argc)
      printf ("%s ", argv[optind++]);
      printf ("\n");
    }

  printf(
  "!!!!!!!!!!!!!!!!!!!!!!!! WARNING !!!!!!!!!!!!!!!!!!!!!!!!\n"
  "!!!!!   THIS PROGRAM WILL LIKELY KILL YOUR COMPUTER !!!!!\n"
  "!!!!!   ulatency may rescue you ;-)                 !!!!!\n"
  "!!!!!   press ctrl+c to stop                        !!!!!\n"
  "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n"
  );

  sleep(3);


  printf ("malloc %d chunks of %d kb (delay %d us):\n", nums, chunk, delay);

  while(1) {
    if(i < nums) {
      tmp = malloc(chunk*1024);
      memset(tmp, 0, chunk*1024);
      printf(".");
      fflush(stdout);
      i++;
    }
    usleep(delay);
  }

  exit (0);
}
