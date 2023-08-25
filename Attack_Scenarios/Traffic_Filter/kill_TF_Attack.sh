#!/bin/bash



 w | grep "curl http" > ~/Attack_Scenarios/Traffic_Filter/killp.txt
PROC=$(awk '{print $2}' ~/Attack_Scenarios/Traffic_Filter/killp.txt)
ps -ft $PROC | grep "bash -c" > ~/Attack_Scenarios/Traffic_Filter/procpath.txt
PATH=$(awk '{print $2}' ~/Attack_Scenarios/Traffic_Filter/procpath.txt)
kill -9 $PATH


