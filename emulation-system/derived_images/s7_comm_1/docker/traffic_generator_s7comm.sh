#!/bin/bash
while [ 1 ]
do
    # Simulate SSH connection 
    sleep 2
    timeout 5 sshpass -p 'testcsleuser' ssh -oStrictHostKeyChecking=no 172.18.8.22 > /dev/null 2>&1
    
    # Snap7 Read DB (Data Block)
    sleep 2
    timeout 5 python3 -c "
import snap7
import time

client = snap7.client.Client()
client.connect('172.18.8.22', 0, 1)  # Rack 0, Slot 1
client.db_read(1, 0, 10)  # Read 10 bytes from DB 1
client.disconnect()
" > /dev/null 2>&1
    
    # Snap7 Write DB
    sleep 2
    timeout 5 python3 -c "
import snap7
import time

client = snap7.client.Client()
client.connect('172.18.8.22', 0, 1)  # Rack 0, Slot 1
data = bytearray(10)
data[0:2] = b'\x12\x34'  # Some example data
client.db_write(1, 0, data)  # Write to DB 1
client.disconnect()
" > /dev/null 2>&1
    
    # Snap7 Read CPU Info
    sleep 2
    timeout 5 python3 -c "
import snap7
import time

client = snap7.client.Client()
client.connect('172.18.8.22', 0, 1)  # Rack 0, Slot 1
client.get_cpu_info()
client.disconnect()
" > /dev/null 2>&1
    
    sleep 2
done