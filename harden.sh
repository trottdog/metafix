#!/usr/bin/env bash

for user in $(awk -F: '$3 >= 1000 && $1 != "nobody" && $1 != "vagrant" {print $1}' /etc/passwd); do
  pkill -u "$user" 2>/dev/null
  userdel -r "$user"
done
