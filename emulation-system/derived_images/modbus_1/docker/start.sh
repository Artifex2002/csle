#!/bin/bash

# Start SSH in background
/usr/sbin/sshd -D &

# Restart rsyslog for logging
service rsyslog restart

# Start OpenPLC Runtime
/opt/OpenPLC_v3/start_openplc.sh &

# Start Modbus Server
python3 /home/modbus_server.py --comm tcp --port 502 --store sequential --slaves 1 &

# Keep container running
tail -f /dev/null