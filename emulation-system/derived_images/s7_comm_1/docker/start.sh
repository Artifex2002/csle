#!/bin/bash

# Start SSH in background
/usr/sbin/sshd -D &

# Restart rsyslog for logging
service rsyslog restart

# Start OpenPLC Runtime
/opt/OpenPLC_v3/start_openplc.sh &

# Start Snap7 Server on default Siemens S7 port 102
python3 -m snap7.server --port 102 &

# Start Beats for logging
service filebeat start
service metricbeat start
service packetbeat start
service auditbeat start
service heartbeat-elastic start

# Keep container running
tail -f /dev/null