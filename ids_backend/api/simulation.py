import subprocess
import threading

ATTACK_COMMANDS = {
    'portscan': ['docker', 'exec', 'kali-attacker', 'sh', '/attacks/portscan_attack.sh'],
    'sqli': ['docker', 'exec', 'kali-attacker', 'sh', '/attacks/sqli_attack.sh'],
    'bruteforce': ['docker', 'exec', 'kali-attacker', 'sh', '/attacks/bruteforce_web_attack.sh'],
    'dos': ['docker', 'exec', 'kali-attacker', 'sh', '/attacks/dos_attack.sh'],
    'xss': ['docker', 'exec', 'kali-attacker', 'sh', '/attacks/xss_attack.sh'],
    # Home-network / IoT scenarios run in the dedicated iot-attacker container
    'iotdos': ['docker', 'exec', 'iot-attacker', 'sh', '/iot_attacks/dos_iot.sh'],
    'iotmitm': ['docker', 'exec', 'iot-attacker', 'sh', '/iot_attacks/mitm_iot.sh'],
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
            'iot-attacker': ['_iot.sh', 'nmap', 'hydra', 'hping3', 'slowhttptest', 'arpspoof', 'ettercap', 'nc'],
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
            ('cicflowmeter', 'rm -f /flows_iot_test/*.csv /flows_iot_test/*.csv.tmp'),
        ]
        for container, cmd in purge_targets:
            try:
                subprocess.run(['docker', 'exec', container, 'sh', '-c', cmd], capture_output=True, timeout=5)
            except Exception as e:
                print(f"Error purging test lane in {container}: {e}")
        return True


def is_attack_running():
    with process_lock:
        return bool(current_process and current_process.poll() is None)
