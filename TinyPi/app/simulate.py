import os
import socket
import time
import random
import datetime as dt

# Where to send the simulated logs
HOST = "192.168.0.118"  # since the script runs inside the container
PORT = int(os.environ.get("PORT", "5514"))  # match the UDP port your SIEM listens on

# Example data sets
apps = ["sshd", "kernel", "unifi", "pihole", "nginx", "dhclient"]
hosts = ["pi", "router", "laptop", "desktop", "switch", "phone"]
msgs = [
    "Accepted password for trent from 192.168.1.10 port 53422 ssh2",
    "Failed password for invalid user admin from 203.0.113.45 port 44210 ssh2",
    "Invalid user test from 198.51.100.7",
    "DHCPREQUEST on eth0 to 255.255.255.255 port 67",
    "kernel: eth0: Link is Up - 1Gbps/Full - flow control off",
    "unifi: STA 11:22:33:44:55:66 connected to wifi Home-5G",
    "nginx: GET /index.html 200 14ms",
]

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

def pri(fac=1, sev=5):  # user.notice
    return f"<{(fac<<3)|sev}>"

# Loop forever sending simulated syslog traffic
while True:
    now = dt.datetime.now().strftime("%b %d %H:%M:%S")
    host = random.choice(hosts)
    app = random.choice(apps)
    msg = random.choice(msgs)
    line = f"{pri()}{now} {host} {app}: {msg}"
    sock.sendto(line.encode(), (HOST, PORT))
    print("Sent:", line)
    time.sleep(random.uniform(0.2, 1.2))
