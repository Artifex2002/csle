# Use Debian 10.2 as a base, similar to Siemens Industrial OS V2 used in Simatic IPCs 
# or industrial PLCs which often embed a small Linux-based RTOS.
FROM debian:10.2
USER root

# Update package index for installing minimal but essential packages.
RUN apt-get update && apt-get install -y --no-install-recommends \
    sudo \
    net-tools \       
    iputils-ping \
    curl \           
    wget \        
    git \     
    nano \           
    openssh-server \
    rsyslog \         
    iptables \       
    python3 python3-pip \
    ntp \             
    openssl \         
    sysstat \          
    && apt-get clean && rm -rf /var/lib/apt/lists/*


# Setup password-less sudo*
RUN mv /etc/sudoers /etc/sudoers.bak
ADD docker_files/common/sudoers /etc/sudoers

# Install ICS-relevant Python libraries, plus csle-collector for data logging.
RUN pip3 install \
    python-opcua \     
    pymodbus \     
    python-snap7 \   
    csle-collector

# Beats
RUN curl -L -O https://artifacts.elastic.co/downloads/beats/filebeat/filebeat-8.3.3-amd64.deb &&\
    dpkg -i filebeat-8.3.3-amd64.deb &&\
    curl -L -O https://artifacts.elastic.co/downloads/beats/metricbeat/metricbeat-8.3.3-amd64.deb &&\
    dpkg -i metricbeat-8.3.3-amd64.deb &&\
    curl -L -O https://artifacts.elastic.co/downloads/beats/packetbeat/packetbeat-8.3.3-amd64.deb &&\
    dpkg -i packetbeat-8.3.3-amd64.deb &&\
    curl -L -O https://artifacts.elastic.co/downloads/beats/auditbeat/auditbeat-8.3.3-amd64.deb &&\
    dpkg -i auditbeat-8.3.3-amd64.deb &&\
    curl -L -O https://artifacts.elastic.co/downloads/beats/heartbeat/heartbeat-8.3.3-amd64.deb &&\
    dpkg -i heartbeat-8.3.3-amd64.deb

# Configure SSH (not typical for a real PLC, but simulates engineering/maintenance access).
# RUN mkdir -p /var/run/sshd && \
#     sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config

# Setup root SSH*
RUN mv /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
ADD docker_files/common/sshd_config_14 /etc/ssh/sshd_config
RUN service ssh start

# Install OpenPLC Runtime
RUN git clone https://github.com/thiagoralves/OpenPLC_v3.git /opt/OpenPLC_v3 && \
    cd /opt/OpenPLC_v3 && \
    ./install.sh docker

# Set OpenPLC Runtime to start automatically

# Expose ICS-related ports:
#  22  = SSH (analogy for engineering port)
#  502 = Modbus default
#  4840 = OPC UA default
#  8080 - Web-based IDE
#  20000 - Internal OpenPLC Communication
# Expose OpenPLC ports
# EXPOSE 22 502 8080 4840 20000

# Include Tini as a simple init system to manage processes and reap zombies in container.
ENV TINI_VERSION v0.19.0
ADD https://github.com/krallin/tini/releases/download/${TINI_VERSION}/tini /tini
RUN chmod +x /tini
ENTRYPOINT ["/tini", "--"]

# (Optional) Copy in scripts for ICS exploits or protocol fuzzing to simulate attacks on the device.
# ADD modbus_exploit.py /modbus_exploit.py
# RUN chmod +x /modbus_exploit.py

# Set OpenPLC Runtime to start automatically
#CMD ["/opt/OpenPLC_v3/start_openplc.sh"]