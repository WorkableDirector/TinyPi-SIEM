# TinyPi-SIEM
TinyPi is a lightweight SIEM software that allows you to view and monitor threats, vulnerabilites, and more by a RaspberryPi or any other machine running an Ubuntu based distribution. 

## Caution
This is a very early prototype!! Most features will not work and only the basic dashboard is working.

## Overview

The system collects logs using syslog, stores them in SQLite, analyzes them through Python scripts, and presents results in a Flask or FastAPI web dashboard. It supports real-time updates and basic security controls aligned with the CIA triad.

## Requirements

* **Operating System:** Raspberry Pi OS Lite or any Ubuntu based distro.
* Python 3.10+
* SQLite 3
* rsyslog or syslog-ng
* Docker and Docker Compose
* _(Docker should install all of these when starting container for the first time.)_

---

## Setup

1. Clone the repository:

   ```
   git clone [https://github.com/WorkableDirector/TinyPi-SIEM](https://github.com/WorkableDirector/TinyPi-SIEM)
   cd TinyPi-SIEM
   cd TinyPi
   ```
2. **Firewall Setup (UFW)**

    If you are using **UFW** (Uncomplicated Firewall) on your host machine, you must open the required ports before running the container. Run these commands:

    ```bash
    sudo ufw allow 8000/tcp
    sudo ufw allow 5514/udp
    sudo ufw reload
    ```
    This opens TCP port **8000** for the web dashboard and UDP port **5514** for syslog log collection. 

3. Build and run the container:

   ```
   sudo docker compose up --build -d
   ```
4. Access the dashboard at `http://<Host IP running TinyPi>:8000`.

## Features

* Centralized log collection
* Basic alert detection (e.g., failed SSH logins)
* Real-time dashboard updates
* Authentication and integrity verification

## License

MIT License
