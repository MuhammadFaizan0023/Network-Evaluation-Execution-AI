# NEXA — Network Evaluation and Execution AI

NEXA is an AI-based Intrusion Detection System for websites and home/IoT networks.

```
Traffic ──► pcaps ──► CICFlowMeter ──► CSV flows ──► Kafka ──► ML consumers ──► Django backend ──► Next.js dashboard
                                                                 ├─ Website lane : CNN model
                                                                 └─ IoT lane     : XGBoost (TON-IoT) model
```

---

## Prerequisites

- **Docker Desktop** (with the engine running)
- **Python 3.10+** for the backend
- **Node.js + npm** for the frontend
- **Wireshark** (`dumpcap` / `tshark`) for capturing IoT camera traffic

## Configuration

Copy the example environment file and adjust if needed:

```powershell
Copy-Item .env.example .env
```

For local Windows (Docker Desktop) keep `NEXA_BACKEND_URL=http://host.docker.internal:8000`, so the ML consumers inside Docker can reach the backend running on your machine.

---

## 1. Start Docker

From the repository root:

```powershell
# First time (or after changing a Dockerfile / model)
docker compose up -d --build

# Normal start
docker compose up -d

# Check that everything is running
docker compose ps

# Follow logs of a service, e.g. the IoT model
docker compose logs -f ml-consumer-iot

# Stop everything
docker compose down
```

| Service                                         | Purpose                                                                    |
| ----------------------------------------------- | -------------------------------------------------------------------------- |
| `dvwa` + `db`                                   | Vulnerable demo website (http://localhost:8080/dvwa)                       |
| `sniffer`                                       | Captures website traffic into `pcaps/`                                     |
| `client1-3`                                     | Generate normal (benign) website traffic                                   |
| `cicflow`                                       | Converts `pcaps/` → `flows/` (website lane)                                |
| `cicflowmeter_iot`                              | Converts `pcaps_iot/` and `pcaps_iot_test/` → normalized flows (IoT lanes) |
| `kafka` / `kafka-producer`                      | Streams flow CSVs to the ML consumers                                      |
| `ml-consumer`                                   | Website CNN model                                                          |
| `ml-consumer-iot`                               | IoT XGBoost model on real camera traffic                                   |
| `ml-consumer-iot-test`                          | IoT model on the Simulation Lab test lane                                  |
| `kali-attacker` / `iot-attacker` / `iot-victim` | Attack simulation containers                                               |
| `nexa-frontend`                                 | Dashboard (http://localhost:3000)                                          |

## 2. Start the backend

In PowerShell:

```powershell
cd ids_backend

# First time only
python -m venv venv

venv\Scripts\Activate.ps1

# First time only (or when requirements change)
pip install -r requirements.txt
# Run server
./venv/bin/python3 -m daphne -b 0.0.0.0 -p 8000 ids_backend.asgi:application
```

- REST API: `http://localhost:8000/api`
- WebSocket: `ws://localhost:8000/ws/dashboard/` (served by `runserver` because `daphne` is installed)
- Optional demo data: `python seed_data.py`

> If PowerShell blocks `Activate.ps1`, run once: `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`

## 3. Start the frontend

The `nexa-frontend` Docker container already serves the dashboard at **http://localhost:3000**.

For local development instead (hot reload), stop the container first so port 3000 is free:

```powershell
docker compose stop nexa-frontend

cd nexa_frontend
npm install          # first time only
npm run dev          # development mode

# or production mode
npm run build
npm start
```

---

## 4. IoT camera setup (Windows Internet Connection Sharing)

The camera is plugged into the laptop's **Ethernet** port. Windows ICS shares the Wi-Fi connection over Ethernet and gives the camera an address in `192.168.137.x`. Run every command in **PowerShell as Administrator**.

> The camera MAC `0c:a6:4c:70:1d:6b` and the Wireshark path `D:\COMSATS\FYP\Wireshark\` are specific to this setup — change them to match yours.

### Step 1 — Disable WSL / Hyper-V virtual adapters

They interfere with ICS.

```powershell
wsl --shutdown
Get-NetAdapter | Where-Object { $_.Name -like "vEthernet*" } | Disable-NetAdapter -Confirm:$false
```

### Step 2 — Reset Internet Connection Sharing

1. Open `ncpa.cpl` → right-click **Wi-Fi** → **Properties** → **Sharing** tab.
2. **Untick** "Allow other network users to connect…" → **OK**.
3. Open it again, **tick** "Allow other network users to connect…", set _Home networking connection_ to **Ethernet** → **OK**.
4. Restart the sharing service:

```powershell
Restart-Service SharedAccess
```

### Step 3 — Confirm the ICS address

```powershell
Get-NetIPAddress -InterfaceAlias "Ethernet" -AddressFamily IPv4 | Select-Object IPAddress
```

The address should be `192.168.137.1`. Check that the ICS DHCP server is listening on UDP port 67:

```powershell
netstat -ano -p udp | findstr ":67 "
```

### Step 4 — Power-cycle the camera

Unplug and replug the camera's **power** (keep the Ethernet cable connected), then wait **90 seconds** so it requests a new IP.

### Step 5 — Find the camera's IP

```powershell
arp -d *
2..254 | ForEach-Object { ping -n 1 -w 300 192.168.137.$_ | Out-Null }
arp -a | Select-String "0c-a6-4c-70-1d-6b"
```

The matching line shows the camera's `192.168.137.x` address.

### Step 6 — Start the capture

Captures only the camera's traffic into `pcaps_iot\`, rotating to a new file every 60 seconds:

```powershell
& "D:\COMSATS\FYP\Wireshark\dumpcap.exe" -i "Ethernet" -f "ether host 0c:a6:4c:70:1d:6b" -w "D:\VS JAVA\NEXA-FYP2\Network-Evaluation-Execution-AI\pcaps_iot\capture.pcap" -b duration:60
```

Keep this window open while capturing. The `cicflowmeter_iot` container picks up each finished file automatically → `flows_iot/` → IoT model → **Home Network** dashboard.

### Step 7 — Verify the capture has real traffic

Replace `<newest_file>` with the latest file name in `pcaps_iot\`:

```powershell
& "D:\COMSATS\FYP\Wireshark\tshark.exe" -r "D:\VS JAVA\NEXA-FYP2\Network-Evaluation-Execution-AI\pcaps_iot\<newest_file>.pcap" -q -z io,phs
```

You should see a protocol hierarchy with real packets (e.g. TCP/UDP), not an empty capture.

### Troubleshooting

- **Camera not found in `arp -a`**: repeat Step 2 (ICS reset) and Step 4 (power-cycle), then scan again.
- **Capture is empty**: check the interface name with `Get-NetAdapter` and that the MAC in the filter is correct.
- **No flows / no alerts**: `docker compose logs -f cicflowmeter_iot` and `docker compose logs -f ml-consumer-iot`.
- **ARP spoofing shows no flows**: expected. ARP is Layer 2 and CICFlowMeter only builds IP flows.

---

## Project structure

| Folder / file                               | Description                                       |
| ------------------------------------------- | ------------------------------------------------- |
| `ids_backend/`                              | Django REST + Channels backend                    |
| `nexa_frontend/`                            | Next.js dashboard                                 |
| `ml_consumer/`                              | Kafka consumer + ML models (CNN, XGBoost)         |
| `kafka_producer/`                           | Streams flow CSVs into Kafka                      |
| `cicflowmeter/`                             | CICFlowMeter image (pcap → flow CSV)              |
| `cicflowmeter_iot/`                         | Feature normalizer for the IoT model              |
| `process_pcaps.sh` / `process_pcaps_iot.sh` | pcap → flow conversion loops (website / IoT)      |
| `attack_simulation/`                        | Simulation Lab test-case banks and injector       |
| `kali_attacks/`, `iot_attacks/`             | Attack scripts run inside the attacker containers |
| `DVWA/`                                     | Vulnerable website used as the web target         |
| `pcaps*/`, `flows*/`                        | Runtime capture and flow data (generated)         |
