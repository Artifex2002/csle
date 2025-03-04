#!/bin/bash

# Start SSH in background
/usr/sbin/sshd -D &

# Restart rsyslog for logging
service rsyslog restart

# Start OpenPLC Runtime
/opt/OpenPLC_v3/start_openplc.sh &

# Start OPC UA Server
python3 /home/opcua_server.py &

# Keep container running
tail -f /dev/null