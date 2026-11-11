# camera_injector — synthetic attacks on the registered camera (HOME-NETWORK lane)

Separate from the **Simulation tab** injector (`attack_simulation/testcases/inject_testcase.py`),
which is **unchanged**. This folder injects synthetic, training-pattern attack flows at your
**registered camera** so the model's live predictions appear on the **Home Network dashboard**.

## How it works
- Reuses the model-verified banks `attack_simulation/testcases/banks/<scenario>.csv` (each row is one
  the model already classifies as its intended class — so the patterns match the TRUSTLab training data).
- **Looks up the camera IP from the UI registration** (`GET /api/devices/`) — nothing is hardcoded.
  Register the camera under **Sources** in the UI (device type `camera`); the injector picks that IP.
- Stamps each flow's **Dst IP** (and rebuilds **Flow ID**) with that registered IP. IPs are metadata,
  not model features, so the prediction is identical — only the displayed target changes.
- Drips `camcase_*.csv` into **`flows_iot`** (the home-network lane) every ~6 s for the duration. The
  producer already watches `flows_iot`, so these interleave with the camera's real flows and both reach
  `ml-consumer-iot` (`source_type=home_network`) → the Home Network dashboard.

## Prerequisites
1. **Register the camera in the UI** (Sources → add device, type `camera`, its IP). The home-network
   ingest only keeps a flow whose Src/Dst IP matches a registered **active** device — stamping the
   registered IP guarantees the match.
2. Stack up: `kafka`, `kafka-producer`, `cicflowmeter_iot`, `ml-consumer-iot`, and the Django backend.
3. The backend must have the ingest fix applied (so `POST /api/flows/ingest/` doesn't 500 on Windows),
   or predictions won't reach the dashboard.

## Run
```
python attack_simulation/camera_injector/inject_camera.py <scenario> [count] [duration] [backend_url] [flows_dir] [bank_dir]
```
Defaults: `count=25`, `duration=60`, `backend_url=http://localhost:8000`,
`flows_dir=<repo>/flows_iot`, `bank_dir=<repo>/attack_simulation/testcases/banks`.

Scenarios: `iotdos, iotddos, iotslowloris, iotbruteforce, iotmitm, iotevasion, iotc2beac, iotexfil, iottlsssl`
(and `benign`).

Example (DDoS at the registered camera for 2 minutes):
```
python attack_simulation/camera_injector/inject_camera.py iotddos 25 120
```

### Choosing which registered device
If several devices are registered, selection order is:
1. `NEXA_CAMERA_IP=<ip>` env (skip the lookup entirely), else
2. `NEXA_DEVICE_NAME="<name>"` env (match a registered device by name), else
3. an active device of type `camera`, else
4. the first active device.

## What you see
On the **Home Network dashboard**, the camera device shows live attack predictions (dos/ddos/… per the
scenario) interleaved with its real benign traffic — in real time.

## Scope / separation
- The **Simulation tab** and its injector (`testcases/inject_testcase.py`, `iot_test` lane) are untouched
  and keep working independently.
- This tool writes only to `flows_iot` and reads the registered IP from the backend; it changes no code.

## Note on injecting at the pcap stage
Injecting these rows during `pcaps_iot → flows_iot` conversion (appending to CICFlowMeter output inside
`process_pcaps_iot.sh`) would also work and would literally co-mingle synthetic + real rows in the same
CSV. It is **not** done here because dropping separate `camcase_*.csv` files into `flows_iot` reaches the
exact same topic/dashboard with far less moving-part risk. Ask if you specifically want the pcap-stage
variant instead.
