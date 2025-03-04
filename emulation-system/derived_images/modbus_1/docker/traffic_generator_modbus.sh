#!/bin/bash
while [ 1 ]
do
    # Simulate SSH connection 
    sleep 2
    timeout 5 sshpass -p 'testcsleuser' ssh -oStrictHostKeyChecking=no 172.18.8.20 > /dev/null 2>&1
    
    # Modbus Read Holding Registers
    sleep 2
    timeout 5 modbus-cli read-holding-registers -h 172.18.8.20 -p 502 -s 1 -r 0 -c 10 > /dev/null 2>&1
    
    # Modbus Write Single Register 
    sleep 2
    timeout 5 modbus-cli write-single-register -h 172.18.8.20 -p 502 -s 1 -r 0 -v 42 > /dev/null 2>&1
    
    # Modbus Read Input Registers
    sleep 2
    timeout 5 modbus-cli read-input-registers -h 172.18.8.20 -p 502 -s 1 -r 0 -c 10 > /dev/null 2>&1
    
    sleep 2
done