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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>


#include <stdio.h>
#include <getopt.h>
#include <string.h>
#include <unistd.h>

int
main (argc, argv)
     int argc;
     char **argv;
{
  int c = 0;
  int i = 0;
  int nums = 2000;
  int delay = 50000;
  int work = 0;
  int rand = open("/dev/urandom",O_RDONLY);
  int data[2];
  int tmpi;
  pid_t pid;


  while (1)
    {
      int option_index = 0;
      static struct option long_options[] =
      {
        {"nums", 1, 0, 'n'},
        {"delay", 1, 0, 'd'},
        {"work", 0, 0, 'w'},
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
          printf ("forkbomb:\n");
          printf ("-n num       number of forks to create\n");
          printf ("-d delay     delay in usecs between alloc \n");
          exit(0);
          break;

        case 'n':
          nums = atoi(optarg);
          break;

        case 'w':
          work = 1;
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


  printf ("fork %d childs %s (delay %d us)e:\n", nums, work ? "working" : "", delay);

  while(1) {
    if(i < nums) {
      pid = fork();
      if(pid < 0) {
        printf("can't fork\n");
      }
      if(pid == 0) {
        printf(".");
        fflush(stdout);
        if(work) {
          read(rand, &data, sizeof(int)*2);
          if(data[1] != 0) {
            tmpi = data[0]/data[1];
          }
        } else {
          sleep(10000);
        }
      }
      i++;
    }
    usleep(delay);
  }

  exit (0);
}
