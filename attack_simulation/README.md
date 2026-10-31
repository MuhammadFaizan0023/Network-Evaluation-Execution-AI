# attack_simulation/ — live test attacks for the new IoT model

Nine live-attack scripts used to **validate the predictions of the new multiclass XGBoost
TON-IoT model** (classes: `Benign, Bruteforce, C2Beac, Evasion, Exfiltracion, MITM, TLSSSL,
ddos, dos, slowloris`).

## How it runs (isolated `iot_test` lane — the real camera is never touched)

```
iot-attacker (172.20.0.201, Kali)  --attack-->  iot-victim (172.20.0.50, lab container)
                                                      |
                                      self-captures its own eth0
                                                      v
   ./pcaps_iot_test/  --cicflow-->  ./flows_iot_test/  --producer-->  kafka topic flows_iot_test
                                                      |
                                      ml-consumer-iot-test (same XGBoost model, SOURCE_TYPE=iot_test)
                                                      v
                                          Django backend  -->  Simulation Lab UI
```

- The target is always the **lab victim `172.20.0.50`**, never the real IP camera.
- `iot_test` flows are **excluded from the main Dashboard/Alerts** on purpose, so they never pollute
  genuine camera history. Results appear on the **Simulation Lab page** (`/simulation`) when the UI
  source toggle is set to **Home Network**.

## How to launch (from the Simulation Lab UI)

1. Make sure these containers are up: `kafka`, `kafka-producer`, `cicflowmeter`,
   `ml-consumer-iot-test`, `iot-attacker`, `iot-victim`, plus the Django backend.
2. In the web UI, set the source to **Home Network**, open **Simulation Lab**, pick a scenario,
   choose duration/intensity, and press **Start**. Each scenario below maps to one script here.

| UI scenario | Script | Expected model class |
|---|---|---|
| DoS | `dos_attack.sh` | `dos` |
| DDoS | `ddos_attack.sh` | `ddos` |
| Slowloris | `slowloris_attack.sh` | `slowloris` |
| Brute Force | `bruteforce_attack.sh` | `Bruteforce` |
| MITM | `mitm_attack.sh` | `MITM` |
| Evasion | `evasion_attack.sh` | `Evasion` |
| C2 Beaconing | `c2beac_attack.sh` | `C2Beac` |
| Exfiltration | `exfiltration_attack.sh` | `Exfiltracion` |
| TLS/SSL | `tlsssl_attack.sh` | `TLSSSL` |

Scripts honor `TARGET_HOST` (default `172.20.0.50`), `INTENSITY` (`low|medium|high`) and
`DURATION` (seconds); the Simulation Lab passes these via `docker exec -e`.

## Honest caveat

These are **real attacks**, so the model predicts whatever it predicts. Script names are the
**intended** category, not a guarantee — `C2Beac`, `Evasion`, `Exfiltracion`, `TLSSSL` are
CIC-ToN-IoT-specific labels whose exact feature distributions come from the training set. The
"Expected vs Detected" readout in the Simulation Lab reports the model's **actual** label; a
mismatch or a Benign is a genuine evaluation finding, not a failure of the harness.
