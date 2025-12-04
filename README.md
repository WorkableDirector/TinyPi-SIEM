# TinyPi-SIEM
TinyPi is a lightweight SIEM software that allows you to view and monitor threats, vulnerabilities, and more using a Raspberry Pi for your UniFi gateway. Also works on machines running most Debian based distributions/

## Caution
This is a very early prototype! There may be features that have not been added yet.



## Overview
The system collects logs using syslog, stores them in SQLite, analyzes them through Python scripts, and presents results in a Flask or FastAPI web dashboard. It supports real-time updates and basic security controls.



## Requirements
* **Operating System:** Raspberry Pi OS or any Debian-based distro
* Python 3.10+
* SQLite 3
* rsyslog or syslog-ng
* Docker and Docker Compose

_(Docker should install all dependencies when the container is built for the first time.)_



## Setup

### 1. Clone the repository
```bash
git clone https://github.com/WorkableDirector/TinyPi-SIEM
cd TinyPi-SIEM
cd TinyPi
```

### 2. Firewall Setup (UFW)
If you are using **UFW** (Uncomplicated Firewall) on your host machine, open the required ports before running the container. Run these commands:

```bash
sudo ufw allow 8000/tcp
sudo ufw allow 5514/udp
sudo ufw reload
```

This opens TCP port **8000** for the web dashboard and UDP port **5514** for syslog log collection. The syslog listener binds to port **5514** by default; you can override it by setting the `SIEM_SYSLOG_PORT` environment variable if your gateway needs a different destination port.

### 3. Build and run the container
```bash
sudo docker compose up --build -d
```

### 4. Access the dashboard
Open your browser and go to:  
`http://<Host IP running TinyPi>:8000`



## Features
* Centralized log collection
* Basic alert detection (e.g., failed SSH logins) (WIP)
* Real-time dashboard updates
* Authentication and integrity verification (WIP)



## License
MIT License
