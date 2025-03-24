import logging
import os
import re
import subprocess
import pathlib
from itertools import product
from datetime import datetime
from string import punctuation
from flask import render_template_string
import json

import pwnagotchi.plugins as plugins
from pwnagotchi.utils import StatusFile
from json.decoder import JSONDecodeError

# Set up basic logging configuration
logging.basicConfig(level=logging.INFO)

# Define the regular expression pattern for crackable handshake
crackable_handshake_re = re.compile(
    r'\s+\d+\s+(?P<bssid>([a-fA-F0-9]{2}:){5}[a-fA-F0-9]{2})\s+(?P<ssid>.+?)\s+((\([1-9][0-9]* handshake(, with PMKID)?\))|(\(\d+ handshake, with PMKID\)))'
)

# Load the HTML template from the file
TEMPLATE_PATH = os.path.join(os.path.dirname(__file__), 'rulesdic.html')
with open(TEMPLATE_PATH, 'r') as file:
    TEMPLATE = file.read()

class RulesDic(plugins.Plugin):
    __authors__ = 'fmatray, AWWShuck'
    __version__ = '1.0.2'
    __license__ = 'GPL3'
    __description__ = 'Tries to crack with hashcat with a generated wordlist based on the wifi name'
    __dependencies__ = {
        'apt': ['hashcat'],
    }

    def __init__(self):
        logging.info("Initializing RulesDic plugin")
        self.options = self._initialize_options()
        self.report = self._load_status_file()
        self.years = self._initialize_years()
        self.running = False
        self.counter = 0
        self.crack_attempts = 0  # Add a counter for crack attempts
        logging.info("Initialization complete")
        logging.info(f"Options set: {self.options}")

    def _load_status_file(self):
        status_file_path = os.path.join(self.options['handshake_path'], '.rulesdic')
        try:
            logging.info(f"Loading status file from {status_file_path}")
            return StatusFile(status_file_path, data_format='json')
        except JSONDecodeError:
            logging.warning("Status file corrupted, creating a new one")
            os.remove(status_file_path)
            return StatusFile(status_file_path, data_format='json')

    def _initialize_options(self):
        logging.info("Initializing options")
        options = {
            'exclude': [],
            'tmp_folder': '/tmp',
            'max_essid_len': 12,
            'face': '(≡·≡)',
            'handshake_path': '/home/pi/handshakes/',
        }
        logging.info(f"Options initialized: {options}")
        return options

    def _initialize_years(self):
        logging.info("Initializing years range for wordlist generation")
        years = list(map(str, range(1900, datetime.now().year + 1)))
        years.extend(map(str, range(0, 100)))
        return years

    def on_loaded(self):
        logging.info('[RulesDic] plugin loaded')
        try:
            check = subprocess.run(
                ['/usr/bin/dpkg', '-l', 'hashcat'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            check_output = check.stdout.strip()
            if 'hashcat' in check_output:
                logging.info('[RulesDic] Found hashcat')
                self.running = True
            else:
                logging.warning('[RulesDic] hashcat is not installed or there was an error!')
                logging.info('[RulesDic] Attempting to install hashcat...')
                install = subprocess.run(
                    ['apt', 'update'],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                if install.returncode != 0:
                    logging.error(f'[RulesDic] Failed to update package list: {install.stderr.strip()}')
                    return

                install = subprocess.run(
                    ['apt', 'install', '-y', 'hashcat'],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                if install.returncode == 0:
                    logging.info('[RulesDic] hashcat installed successfully')
                    self.running = True
                else:
                    logging.error(f'[RulesDic] Failed to install hashcat: {install.stderr.strip()}')
        except Exception as e:
            logging.error(f'[RulesDic] Exception occurred: {str(e)}')

    def on_config_changed(self, config):
        logging.info("Configuration changed")
        self.options['handshakes'] = config['bettercap']['handshakes']
        if 'handshake_path' in config:
            self.options['handshake_path'] = config['handshake_path']
        if 'process_existing' in config:
            self.options['process_existing'] = config['process_existing']
        logging.info(f"Options updated: {self.options}")

    def on_handshake(self, agent, filename, access_point, client_station):
        if not self.running:
            logging.info('[RulesDic] Plugin not running, handshake ignored')
            return

        logging.info(f'[RulesDic] Processing handshake for {filename}')
        reported = self.report.data_field_or('reported', default=[])
        excluded = self.report.data_field_or('excluded', default=[])
        essid = os.path.splitext(os.path.basename(filename))[0].split("_")[0]
        if filename in reported:
            logging.info(f'[RulesDic] {filename} already processed')
            return

        # Ensure 'exclude' key exists
        if 'exclude' not in self.options:
            self.options['exclude'] = []

        if filename in excluded or any(re.match(pattern, essid) for pattern in self.options['exclude']):
            excluded.append(filename)
            self.report.update(data={'reported': reported, 'excluded': excluded})
            logging.info(f'[RulesDic] {filename} excluded')
            return

        display = agent.view()
        display.set('face', self.options['face'])
        display.set('status', 'Captured new handshake')
        logging.info(f'[RulesDic] New handshake {filename}')
        current_time = datetime.now()

        result = self.check_handshake(filename)
        if not result:
            logging.info('[RulesDic] No handshake')
            display.set('face', self.options['face'])
            display.set('status', 'No handshake found, next time perhaps...')
            return

        bssid = result.group('bssid')
        display.set('face', self.options['face'])
        display.set('status', 'Handshake found')
        logging.info('[RulesDic] Handshake confirmed')

        display.set('status', 'Cracking in progress...')
        self.update_progress_status(filename, 'Cracking in progress...')
        logging.info(f'[RulesDic] Before incrementing crack attempts')
        self.crack_attempts += 1  # Increment crack attempts counter
        logging.info(f'[RulesDic] Crack attempts incremented: {self.crack_attempts}')  # Log crack attempts

        pwd = self.try_to_crack(filename, essid, bssid)
        duration = (datetime.now() - current_time).total_seconds()

        if not pwd:
            display.set('face', self.options['face'])
            display.set('status', f'Password not found for {essid} :\'()')
            self.update_progress_status(filename, 'Password not found')
            logging.warning(
                f'!!! [RulesDic] !!! Key not found for {essid} in {duration // 60:.0f}min and {duration % 60:.0f}s')
        else:
            display.set('face', self.options['face'])
            display.set('status', f'Password cracked for {essid} :\'()')
            self.update_progress_status(filename, 'Password cracked')
            logging.warning(
                f'!!! [RulesDic] !!! Cracked password for {essid}: {pwd}. Found in {duration // 60:.0f}min and {duration % 60:.0f}s')

        reported.append(filename)
        self.report.update(data={'reported': reported, 'excluded': excluded})
        self.update_progress_status(filename, 'Handshake cracks attempted: {}'.format(self.crack_attempts))  # Update progress status with crack attempts

    def update_progress_status(self, filename, status):
        try:
            logging.info(f"Updating progress status for {filename}")
            passwords = []
            handshake_path = pathlib.Path(self.options['handshake_path'])
            cracked_files = handshake_path.glob('*.cracked')
            for cracked_file in cracked_files:
                ssid, bssid = re.findall(r"(.*)_([0-9a-f]{12})\.", cracked_file.name)[0]
                with open(cracked_file, 'r') as f:
                    pwd = f.read()
                passwords.append({"ssid": ssid, "bssid": bssid, "password": pwd, "status": status})

            # Ensure the JSON log files exist
            log_files = ['checked_wifis.json', 'crack_attempts.json', 'successful_cracks.json']
            for log_file in log_files:
                if not os.path.exists(log_file):
                    with open(log_file, 'w') as f:
                        f.write('[]')

            # Load logs for checked Wi-Fi networks and crack attempts
            with open('checked_wifis.json', 'r') as log_file:
                checked_wifis = json.load(log_file)
            with open('crack_attempts.json', 'r') as log_file:
                crack_attempts = json.load(log_file)
            with open('successful_cracks.json', 'r') as log_file:
                successful_cracks = json.load(log_file)

            return render_template_string(
                TEMPLATE,
                title="Passwords list",
                passwords=passwords,
                crack_attempts=self.crack_attempts,
                checked_wifis=checked_wifis,
                crack_attempts_log=crack_attempts,
                successful_cracks=successful_cracks
            )
        except Exception as e:
            logging.error(f"[RulesDic] error while updating progress status: {e}")
            logging.debug(e, exc_info=True)

    def check_handshake(self, filename):
        # Execute hashcat to check if the handshake is crackable
        logging.info(f"Running hashcat to check handshake for {filename}")
        hashcat_command = f'nice hashcat -m 22000 {filename} --show'
        hashcat_execution = subprocess.run(
            hashcat_command, shell=True, stdout=subprocess.PIPE)
        result = hashcat_execution.stdout.decode('utf-8', errors='replace').strip()

        # Ensure the checked_wifis.json file exists
        if not os.path.exists('checked_wifis.json'):
            with open('checked_wifis.json', 'w') as f:
                f.write('[]')

        # Log the checked Wi-Fi network
        with open('checked_wifis.json', 'a') as log_file:
            log_entry = {"filename": filename, "result": result}
            log_file.write(json.dumps(log_entry) + '\n')

        if result:
            return crackable_handshake_re.search(result)
        else:
            return None

    def try_to_crack(self, filename, essid, bssid):
        wordlist_filename = self._generate_dictionary(filename, essid)
        command = f'nice /usr/bin/hashcat -m 22000 {filename}.pcapng -a 0 -w 3 -o {filename}.cracked {wordlist_filename}'
        logging.info(f'[RulesDic] Running hashcat with command: {command}')  # Log hashcat command
        subprocess.run(command, shell=True, stdout=subprocess.PIPE)
        result = pathlib.Path(f"{filename}.cracked").read_text().strip()

        # Ensure the crack_attempts.json file exists
        if not os.path.exists('crack_attempts.json'):
            with open('crack_attempts.json', 'w') as f:
                f.write('[]')

        # Log the crack attempt
        with open('crack_attempts.json', 'a') as log_file:
            log_entry = {"filename": filename, "essid": essid, "bssid": bssid, "status": "attempted"}
            log_file.write(json.dumps(log_entry) + '\n')

        if result:
            # Ensure the successful_cracks.json file exists
            if not os.path.exists('successful_cracks.json'):
                with open('successful_cracks.json', 'w') as f:
                    f.write('[]')

            # Log the successful crack
            with open('successful_cracks.json', 'a') as log_file:
                log_entry = {"filename": filename, "essid": essid, "bssid": bssid, "password": result.split(':')[1]}
                log_file.write(json.dumps(log_entry) + '\n')
            return result.split(':')[1]
        return None

    def _generate_dictionary(self, filename, essid):
        wordlist_filename = os.path.join(self.options['tmp_folder'], f"{os.path.splitext(os.path.basename(filename))[0]}.txt")
        logging.info(f'[RulesDic] Generating {wordlist_filename}')
        essid_bases = self._essid_base(essid)
        wordlist = essid_bases + self._reverse_rule(essid_bases) + self._punctuation_rule(essid_bases) + self._years_rule(essid_bases)

        if self.options['max_essid_len'] == -1 or len(essid) <= self.options['max_essid_len']:
            logging.info(f'[RulesDic] Generating leet wordlist')
            wordlist += self._leet_rule(essid)

        wordlist = list(dict.fromkeys(wordlist))
        with open(wordlist_filename, "w") as f:
            f.write('\n'.join(wordlist))
        logging.info(f'[RulesDic] {len(wordlist)} password generated')
        return wordlist_filename

    def _essid_base(self, essid):
        logging.info(f"Generating base wordlist for ESSID {essid}")
        return [essid, essid.upper(), essid.lower(), essid.capitalize(), re.sub('[0-9]*$', "", essid)]

    def _reverse_rule(self, base_essids):
        logging.info("Applying reverse rule")
        return [essid[::-1] for essid in base_essids]

    def _punctuation_rule(self, base_essids):
        logging.info("Applying punctuation rule")
        wd = ["".join(p) for p in product(base_essids, punctuation)]
        wd += ["".join(p) for p in product(base_essids, punctuation, punctuation)]
        wd += ["".join(p) for p in product(base_essids, punctuation)]
        wd += ["".join(p) for p in product(punctuation, base_essids, punctuation)]
        return wd

    def _years_rule(self, base_essids):
        logging.info("Applying years rule")
        wd = ["".join(p) for p in product(base_essids, self.years)]
        wd += ["".join(p) for p in product(base_essids, self.years, punctuation)]
        wd += ["".join(p) for p in product(base_essids, punctuation, self.years)]
        return wd

    def _leet_rule(self, essid):
        logging.info("Applying leet rule")
        leet_dict = {
            'a': ['4', '@', 'a', 'A'], 'b': ['8', '6', 'b', 'B'], 'c': ['(', '<', '{', '[', 'c', 'C'], 'd': ['d', 'D'],
            'e': ['3', 'e', 'E'], 'f': ['f', 'F'], 'g': ['6', '9', 'g', 'G'], 'h': ['#', 'h', 'H'], 'i': ['!', '|', '1', 'i', 'I'],
            'j': ['j', 'J'], 'k': ['k', 'K'], 'l': ['1', 'l', 'L'], 'm': ['m', 'M'], 'n': ['n', 'N'], 'o': ['0', 'o', 'O'],
            'p': ['p', 'P'], 'q': ['q', 'Q'], 'r': ['r', 'R'], 's': ['5', '$', 's', 'S'], 't': ['7', '+', 't', 'T'], 'u': ['u', 'U'],
            'v': ['v', 'V'], 'w': ['w', 'W'], 'x': ['x', 'X'], 'y': ['y', 'Y'], 'z': ['2', 'z', 'Z'], '0': ['o', 'O', '0'],
            '1': ['i', 'I', '1'], '2': ['r', 'R', '2'], '3': ['e', 'E', '3'], '4': ['a', 'A', '4'], '5': ['s', 'S', '5'],
            '6': ['b', 'B', '6'], '7': ['y', 'Y', '7'], '8': ['b', 'B', '8'], '9': ['g', 'G', '9']
        }
        transformations = [leet_dict.get(c, c) for c in essid.lower()]
        return [''.join(p) for p in product(*transformations)]

    # Handle webhooks for the plugin
    def on_webhook(self, path, request):
        if not self.running:
            return
        if path == "/" or not path:
            try:
                logging.info("Handling webhook")
                passwords = []
                handshake_path = pathlib.Path(self.options['handshake_path'])
                cracked_files = handshake_path.glob('*.cracked')
                for cracked_file in cracked_files:
                    ssid, bssid = re.findall(r"(.*)_([0-9a-f]{12})\.", cracked_file.name)[0]
                    with open(cracked_file, 'r') as f:
                        pwd = f.read()
                    passwords.append({"ssid": ssid, "bssid": bssid, "password": pwd, "status": "Cracked"})

                # Ensure the JSON log files exist
                log_files = ['checked_wifis.json', 'crack_attempts.json', 'successful_cracks.json']
                for log_file in log_files:
                    if not os.path.exists(log_file):
                        with open(log_file, 'w') as f:
                            f.write('[]')

                # Load logs for checked Wi-Fi networks and crack attempts
                with open('checked_wifis.json', 'r') as log_file:
                    checked_wifis = json.load(log_file)
                with open('crack_attempts.json', 'r') as log_file:
                    crack_attempts = json.load(log_file)
                with open('successful_cracks.json', 'r') as log_file:
                    successful_cracks = json.load(log_file)

                return render_template_string(
                    TEMPLATE,
                    title="Passwords list",
                    passwords=passwords,
                    crack_attempts=self.crack_attempts,
                    checked_wifis=checked_wifis,
                    crack_attempts_log=crack_attempts,
                    successful_cracks=successful_cracks
                )
            except Exception as e:
                logging.error(f"[RulesDic] error while updating progress status: {e}")
                logging.debug(e, exc_info=True)
