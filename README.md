# TinyPi-SIEM
TinyPi is a lightweight SIEM software that allows you to view and monitor threats, vulnerabilites, and more by using a simple Raspberry Pi-5)

## Caution
This is a very early prototype!! Most features will not work and only the basic dashboard is working.

## Overview

The system collects logs using syslog, stores them in SQLite, analyzes them through Python scripts, and presents results in a Flask or FastAPI web dashboard. It supports real-time updates and basic security controls aligned with the CIA triad.

## Requirements

* Raspberry Pi OS Lite or AlmaLinux
* Python 3.10+
* SQLite 3
* rsyslog or syslog-ng
* Docker and Docker Compose
* _(Docker should install all of these when starting container for the first time.)_

## Setup

1. Clone the repository:

   ```bash
   git clone https://github.com/WorkableDirector/TinyPi-SIEM
   cd TinyPi-SIEM
   cd TinyPi
   ```
2. Build and run the container:

   ```bash
   sudo docker compose up --build -d
   ```
3. Access the dashboard at `http://<Host IP running TinyPi>:8000`.

## Features

* Centralized log collection
* Basic alert detection (e.g., failed SSH logins)
* Real-time dashboard updates
* Authentication and integrity verification

## License

MIT License
