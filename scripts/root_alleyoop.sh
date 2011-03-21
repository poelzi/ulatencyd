#!/bin/sh
sudo su -c 'env G_SLICE=always-malloc dbus-launch --exit-with-session alleyoop src/ulatencyd -v 3'
