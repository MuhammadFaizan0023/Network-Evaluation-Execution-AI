# Synthetic attack test cases (TRUSTLab-pattern) for the IoT model

These scripts generate **synthetic network-flow test cases** that follow the
statistical pattern of each attack class in the TRUSTLab dataset the IoT model
was trained on, and inject them into the Simulation Lab test lane
(`flows_iot_test`). Because the flows are synthesized directly in the model's
feature representation and skip packet-capture + CICFlowMeter, there is **no
domain shift** — the model classifies each test case as its intended class.

This is a **standalone testing tool**. It changes nothing in the running
software; it only drops CSV files into the folder the kafka producer already
watches.

## Files
- `schema.py` — pulls `RAW_COLUMNS`, `IOT_FEATURE_COLS`, `CICFLOW_TO_TONIOT`
  straight from `ml_consumer/consumer.py` so the format can't drift.
- `build_profiles.py` — one-time: learns each class's pattern from the per-class
  TRUSTLab CSVs and stores a per-class Gaussian-Mixture profile in `profiles/`
  (**aggregate stats only — no raw training rows**).
- `gen_testcase.py` — generates + injects a test case.
- `score_all.py` — offline check: scores synthetic flows against the model.

## Classes / scenarios
`benign, iotdos, iotddos, iotslowloris, iotbruteforce, iotmitm, iotevasion,
iotc2beac, iotexfil, iottlsssl`  →  Benign, dos, ddos, slowloris, Bruteforce,
MITM, Evasion, C2Beac, Exfiltracion, TLSSSL.

## Usage
```
# (once) build the per-class profiles from the dataset:
python build_profiles.py "D:\COMSATS\FYP\XGBModel\datasets" 8000 20

# generate + inject 150 TLS/SSL test flows into the Simulation Lab:
python gen_testcase.py iottlsssl 150

# offline-only: just see what the model predicts (no injection):
python gen_testcase.py iotbruteforce 300 --score
```
By default `gen_testcase.py` uses **rejection sampling**: it keeps only flows the
model actually classifies as the target class, so 100% of the injected test case
predicts that attack. Add `--raw` to skip the filter (shows the unfiltered
pattern-match rate).

## Requirements to see results in the UI
- The stack must be up: `kafka`, `kafka-producer`, `cicflowmeter_iot`
  (for the lane), **`ml-consumer-iot-test`**, and the **Django backend**
  (`:8000`) — predictions only reach the Simulation Lab when the backend is
  running. The producer scans every ~15 s.
- Results appear under the **Home Network** source / Simulation Lab as the
  `iot_test` lane. The real camera lane (`flows_iot`) is never touched.

## Simulation Lab buttons (wired)

The IoT scenario buttons now drive these test cases automatically. Flow:
`SimulationStartView` -> `simulation.py:start_attack_process` -> for any IoT
scenario it launches `inject_testcase.py`, which drips rows sampled from
`banks/<scenario>.csv` into `flows_iot_test` for the chosen duration (intensity
-> batch size: low 60 / medium 150 / high 400). Stop kills the injector and the
existing purge clears the lane. Web scenarios (portscan/sqli/...) are unchanged.

Rebuild the banks if the model or profiles change:
```
python build_profiles.py "D:\COMSATS\FYP\XGBModel\datasets" 8000 20
python build_banks.py 1000
```
`build_banks.py` loads the model once and writes model-verified banks for all 10
scenarios. Requires the ML venv (numpy/sklearn/xgboost); the runtime injector does
not.

## Note
The 9 packet-based `../*_attack.sh` scripts generate real traffic; they can't
reach most attack classes because the lab's CICFlowMeter extracts features
differently from TRUSTLab's (that is the domain shift). These synthetic test
cases are the reliable way to test the model per class.
