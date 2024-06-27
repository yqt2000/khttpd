#!/usr/bin/env bash

KHTTPD_MOD=khttpd.ko

if [ "$EUID" -eq 0 ]
  then echo "Don't run this script as root"
  exit
fi

# load kHTTPd
sudo rmmod -f khttpd 2>/dev/null
sleep 1
sudo insmod $KHTTPD_MOD WWWROOT='"/home/oldwustd1/linux2024"'

# run HTTP benchmarking
#./htstress -n 100000 -c 1 -t 4 http://localhost:8081/
./htstress http://localhost:8081 -t 3 -c 20 -n 200000

# epilogue
sudo rmmod khttpd
echo "Complete"
