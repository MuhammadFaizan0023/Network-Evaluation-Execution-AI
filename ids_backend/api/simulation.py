import os
import sys
import glob
import subprocess
import threading

# ── IoT test-case injection (synthetic TRUSTLab-pattern flows) ────────────────
# IoT scenarios no longer run the packet shell scripts (their captured features
# suffer domain shift and read Benign). Instead they inject pre-validated
# synthetic flows straight into the flows_iot_test lane via inject_testcase.py.
_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO = os.path.abspath(os.path.join(_HERE, "..", ".."))          # repo root
_TESTCASES = os.path.join(_REPO, "attack_simulation", "testcases")
_INJECTOR = os.path.join(_TESTCASES, "inject_testcase.py")
_BANK_DIR = os.path.join(_TESTCASES, "banks")
_FLOWS_TEST_DIR = os.path.join(_REPO, "flows_iot_test")
IOT_TESTCASE_SCENARIOS = {
    "iotdos", "iotddos", "iotslowloris", "iotbruteforce", "iotmitm",
    "iotevasion", "iotc2beac", "iotexfil", "iottlsssl", "benign",
}
# Per-BATCH flow count (the injector drips one batch every ~6 s for the run's
# duration). Kept small so the lane/Kafka never backs up.
INTENSITY_COUNT = {"low": 15, "medium": 25, "high": 40}


def _purge_test_lane():
    """Delete the previous run's injected test-case files so each simulation
    starts clean (no stale flows lingering or getting replayed to the model)."""
    try:
        for f in glob.glob(os.path.join(_FLOWS_TEST_DIR, "testcase_*.csv")):
            try:
                os.remove(f)
            except OSError:
                pass
    except Exception as e:
        print(f"test-lane purge error: {e}")

ATTACK_COMMANDS = {
    'portscan': ['docker', 'exec', 'kali-attacker', 'sh', '/attacks/portscan_attack.sh'],
    'sqli': ['docker', 'exec', 'kali-attacker', 'sh', '/attacks/sqli_attack.sh'],
    'bruteforce': ['docker', 'exec', 'kali-attacker', 'sh', '/attacks/bruteforce_web_attack.sh'],
    'dos': ['docker', 'exec', 'kali-attacker', 'sh', '/attacks/dos_attack.sh'],
    'xss': ['docker', 'exec', 'kali-attacker', 'sh', '/attacks/xss_attack.sh'],
    # Home-network / IoT scenarios run in the dedicated iot-attacker container.
    # New multiclass TON-IoT model test-attack suite (attack_simulation/), one
    # script per model class, all targeting the isolated victim 172.20.0.50.
    'iotdos': ['docker', 'exec', 'iot-attacker', 'sh', '/attack_simulation/dos_attack.sh'],
    'iotddos': ['docker', 'exec', 'iot-attacker', 'sh', '/attack_simulation/ddos_attack.sh'],
    'iotslowloris': ['docker', 'exec', 'iot-attacker', 'sh', '/attack_simulation/slowloris_attack.sh'],
    'iotbruteforce': ['docker', 'exec', 'iot-attacker', 'sh', '/attack_simulation/bruteforce_attack.sh'],
    'iotmitm': ['docker', 'exec', 'iot-attacker', 'sh', '/attack_simulation/mitm_attack.sh'],
    'iotevasion': ['docker', 'exec', 'iot-attacker', 'sh', '/attack_simulation/evasion_attack.sh'],
    'iotc2beac': ['docker', 'exec', 'iot-attacker', 'sh', '/attack_simulation/c2beac_attack.sh'],
    'iotexfil': ['docker', 'exec', 'iot-attacker', 'sh', '/attack_simulation/exfiltration_attack.sh'],
    'iottlsssl': ['docker', 'exec', 'iot-attacker', 'sh', '/attack_simulation/tlsssl_attack.sh'],
    # Legacy (old-model) IoT scripts — kept for backward compatibility; not shown
    # in the current Simulation Lab dropdown.
    'iotransomware': ['docker', 'exec', 'iot-attacker', 'sh', '/iot_attacks/ransomware_iot.sh'],
    'iotbackdoor': ['docker', 'exec', 'iot-attacker', 'sh', '/iot_attacks/backdoor_iot.sh'],
    'iotrecon': ['docker', 'exec', 'iot-attacker', 'sh', '/iot_attacks/recon_iot.sh'],
    'iotbenign': ['docker', 'exec', 'iot-attacker', 'sh', '/iot_attacks/benign_iot.sh'],
}

current_process = None
process_lock = threading.Lock()


def start_attack_process(attack_type, target=None, intensity=None, duration=None):
    global current_process
    raw = str(attack_type or '').lower().replace(' ', '').replace('_', '').replace('-', '')
    # IoT / home-network scenarios are matched first (ids are 'iot'-prefixed) so e.g.
    # 'iotdos' does not fall through to the generic web 'dos' branch below.
    if raw.startswith('iot'):
        iot_key = raw if raw in ATTACK_COMMANDS else None
        if iot_key is None:
            if 'ransom' in raw:
                iot_key = 'iotransomware'
            elif 'backdoor' in raw:
                iot_key = 'iotbackdoor'
            elif 'mitm' in raw:
                iot_key = 'iotmitm'
            elif 'recon' in raw or 'access' in raw or 'scan' in raw:
                iot_key = 'iotrecon'
            elif 'benign' in raw or 'normal' in raw:
                iot_key = 'iotbenign'
            elif 'dos' in raw:
                iot_key = 'iotdos'
        clean_key = iot_key or raw
    elif 'portscan' in raw or 'nmap' in raw:
        clean_key = 'portscan'
    elif 'sql' in raw:
        clean_key = 'sqli'
    elif 'brute' in raw:
        clean_key = 'bruteforce'
    elif 'dos' in raw or 'hping' in raw:
        clean_key = 'dos'
    elif 'xss' in raw:
        clean_key = 'xss'
    else:
        clean_key = raw

    # IoT scenarios -> inject synthetic test-case flows (no packets, no domain
    # shift). Web scenarios fall through to the docker-exec packet attacks below.
    iot_scenario = None
    if clean_key in IOT_TESTCASE_SCENARIOS:
        iot_scenario = clean_key
    elif raw.startswith('iot') and ('benign' in raw or 'normal' in raw):
        iot_scenario = 'benign'

    if iot_scenario is not None:
        count = INTENSITY_COUNT.get(str(intensity or 'medium').lower(), 150)
        try:
            dur = int(duration) if duration else 60
        except (TypeError, ValueError):
            dur = 60
        command = [sys.executable, _INJECTOR, iot_scenario, str(count), str(dur),
                   _FLOWS_TEST_DIR, _BANK_DIR]
        with process_lock:
            # Supersede any still-running injector (so switching scenarios works
            # without pressing Stop first), then wipe the previous run's files so
            # only the newly pressed scenario is processed.
            if current_process and current_process.poll() is None:
                try:
                    current_process.kill()
                except Exception:
                    pass
            _purge_test_lane()
            try:
                current_process = subprocess.Popen(command)
                print(f"Started IoT test-case injection: {command}")
            except Exception as e:
                print(f"Error launching test-case injector: {e}")
            return current_process

    base_command = ATTACK_COMMANDS.get(clean_key)
    if not base_command:
        print(f"Unknown attack type: '{attack_type}' (normalized: '{clean_key}')")
        return None

    # Pass runtime config to the script via env vars. TARGET_HOST was already
    # supported; INTENSITY and DURATION drive the per-scenario rate/length.
    env_args = []
    if target:
        env_args += ['-e', f'TARGET_HOST={target}']
    if intensity:
        env_args += ['-e', f'INTENSITY={intensity}']
    if duration:
        env_args += ['-e', f'DURATION={duration}']

    if env_args:
        # base_command is ['docker', 'exec', <container>, 'sh', <script>]; keep the
        # scenario's own container (kali-attacker for web, iot-attacker for IoT).
        container = base_command[2]
        command = ['docker', 'exec'] + env_args + [container, 'sh', base_command[-1]]
    else:
        command = base_command

    with process_lock:
        if current_process and current_process.poll() is None:
            return current_process
        try:
            current_process = subprocess.Popen(command)
            print(f"Started attack command: {command}")
        except Exception as e:
            print(f"Error launching attack process: {e}")
        return current_process


def stop_attack_process():
    global current_process
    with process_lock:
        if current_process:
            if current_process.poll() is None:
                current_process.kill()
            current_process = None
        
        # Kill any orphaned attack processes inside the attacker containers
        kill_targets = {
            'kali-attacker': ['attack.sh', 'nmap', 'hydra', 'hping3', 'sqlmap', 'slowhttptest'],
            'iot-attacker': ['_iot.sh', '_attack.sh', 'nmap', 'hydra', 'hping3', 'slowhttptest', 'arpspoof', 'ettercap', 'nc', 'openssl', 'curl'],
        }
        for container, patterns in kill_targets.items():
            for pattern in patterns:
                try:
                    subprocess.run(['docker', 'exec', container, 'pkill', '-f', pattern], capture_output=True, timeout=3)
                except Exception as e:
                    print(f"Error killing '{pattern}' in {container}: {e}")

        # Hard stop: purge the isolated test lane so already-captured traffic does
        # not keep producing flows after Stop. Only the *_test folders are touched.
        purge_targets = [
            ('iot-victim', 'rm -f /pcaps_iot_test/*.pcap'),
            # flows_iot_test is mounted in cicflowmeter_iot (NOT cicflowmeter).
            ('cicflowmeter_iot', 'rm -f /flows_iot_test/*.csv /flows_iot_test/*.csv.tmp'),
        ]
        for container, cmd in purge_targets:
            try:
                subprocess.run(['docker', 'exec', container, 'sh', '-c', cmd], capture_output=True, timeout=5)
            except Exception as e:
                print(f"Error purging test lane in {container}: {e}")

        # Also purge host-side (backend runs on the host) so the injected
        # test-case files are reliably removed even if the docker exec fails.
        _purge_test_lane()
        return True


def is_attack_running():
    with process_lock:
        return bool(current_process and current_process.poll() is None)
