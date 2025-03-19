import logging
import os
import re
import subprocess
import pathlib
from itertools import product
from datetime import datetime
from string import punctuation
from flask import Flask, render_template_string

import pwnagotchi.plugins as plugins
from pwnagotchi.utils import StatusFile
from json.decoder import JSONDecodeError

app = Flask(__name__)

# HTML template for rendering the passwords list
TEMPLATE = """
{% extends "base.html" %}
{% set active_page = "passwordsList" %}

{% block title %}
    {{ title }}
{% endblock %}

{% block meta %}
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, user-scalable=0" />
{% endblock %}

{% block styles %}
    {{ super() }}
    <style>
        #searchText {
            width: 100%;
        }
        table {
            table-layout: auto;
            width: 100%;
            border: 1px solid;
            border-collapse: collapse;
        }
        th, td {
            padding: 15px;
            text-align: left;
            border: 1px solid;
        }
        @media screen and (max-width: 700px) {
            table, tr, td {
                padding: 0;
                border: 1px solid;
            }
            table {
                border: none;
            }
            tr:first-child, thead, th {
                display: none;
                border: none;
            }
            tr {
                float: left;
                width: 100%;
                margin-bottom: 2em;
            }
            td {
                float: left;
                width: 100%;
                padding: 1em;
            }
            td::before {
                content: attr(data-label);
                word-wrap: break-word;
                color: white;
                border-right: 2px solid;
                width: 20%;
                float: left;
                padding: 1em;
                font-weight: bold;
                margin: -1em 1em -1em -1em;
            }
        }
    </style>
{% endblock %}

{% block script %}
    <script>
        document.addEventListener('DOMContentLoaded', function() {
            var searchInput = document.getElementById('searchText');
            searchInput.onkeyup = function() {
                var filter = searchInput.value.toUpperCase();
                var table = document.getElementById('tableOptions');
                if (table) {
                    var tr = table.getElementsByTagName('tr');
                    for (var i = 0; i < tr.length; i++) {
                        var td = tr[i].getElementsByTagName('td')[0];
                        if (td) {
                            var txtValue = td.textContent || td.innerText;
                            tr[i].style.display = txtValue.toUpperCase().indexOf(filter) > -1 ? '' : 'none';
                        }
                    }
                }
            }
        });
    </script>
{% endblock %}

{% block content %}
    <input type="text" id="searchText" placeholder="Search for ..." title="Type in a filter">
    <div id="progressStatus" style="display: none;">
        <p id="progressMessage">Cracking in progress...</p>
    </div>
    <p id="crackAttempts">Handshakes Cracks Attempted: {{ crack_attempts }}</p>
    <a href="/passwords">View Cracked Passwords</a> <!-- Added link -->
    <table id="tableOptions">
        <thead>
            <tr>
                <th>SSID</th>
                <th>BSSID</th>
                <th>Password</th>
                <th>Status</th>
            </tr>
        </thead>
        <tbody>
            {% for p in passwords %}
                <tr>
                    <td data-label="SSID">{{ p["ssid"] }}</td>
                    <td data-label="BSSID">{{ p["bssid"] }}</td>
                    <td data-label="Password">{{ p["password"] }}</td>
                    <td data-label="Status">{{ p["status"] }}</td>
                </tr>
            {% endfor %}
        </tbody>
    </table>
{% endblock %}
"""

@app.route('/passwords')
def passwords_page():
    passwords = []
    cracked_files = pathlib.Path('/home/pi/handshakes/').glob('*.cracked')
    for cracked_file in cracked_files:
        ssid, bssid = re.findall(r"(.*)_([0-9a-f]{12})\.", cracked_file.name)[0]
        with open(cracked_file, 'r') as f:
            pwd = f.read()
        passwords.append({"ssid": ssid, "bssid": bssid, "password": pwd, "status": "Cracked"})
    return render_template_string(TEMPLATE, title="Passwords List", passwords=passwords, crack_attempts=0)

class RulesDic(plugins.Plugin):
    __authors__ = 'fmatray, awwshucks'
    __version__ = '1.0.2'
    __license__ = 'GPL3'
    __description__ = 'Tries to crack with hashcat with a generated wordlist base on the wifi name'
    __dependencies__ = {
        'apt': ['hashcat'],
    }

    def __init__(self):
        self.report = self._load_status_file()
        self.options = self._initialize_options()
        self.years = self._initialize_years()
        self.running = False
        self.counter = 0
        self.crack_attempts = 0  # Add a counter for crack attempts

    def _load_status_file(self):
        try:
            return StatusFile('/root/handshakes/.rulesdic', data_format='json')
        except JSONDecodeError:
            os.remove('/root/handshakes/.rulesdic')
            return StatusFile('/root/handshakes/.rulesdic', data_format='json')

    def _initialize_options(self):
        return {'exclude': [], 'tmp_folder': '/tmp', 'max_essid_len': 12, 'face': '(≡·≡)'}

    def _initialize_years(self):
        years = list(map(str, range(1900, datetime.now().year + 1)))
        years.extend(map(str, range(0, 100)))
        return years

    def on_loaded(self):
        logging.info('[RulesDic] plugin loaded')
        check = subprocess.run(
            '/usr/bin/dpkg -l hashcat | grep hashcat | gawk \'{print $2, $3}\'',
            shell=True,
            stdout=subprocess.PIPE
        )
        check_output = check.stdout.decode('utf-8').strip()
        if check.returncode == 0 and check_output != "hashcat <none>":
            logging.info('[RulesDic] Found %s' % check_output)
            self.running = True
        else:
            logging.warning('[RulesDic] hashcat is not installed or there was an error!')
            if check.stderr:
                logging.error(f'Error: {check.stderr.decode("utf-8").strip()}')

    def on_config_changed(self, config):
        self.options['handshakes'] = config['bettercap']['handshakes']

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

        result = self.check_handcheck(filename)
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
        logging.info('[RulesDic] Before incrementing crack attempts')
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
            passwords = []
            cracked_files = pathlib.Path('/home/pi/handshakes/').glob('*.cracked')
            for cracked_file in cracked_files:
                ssid, bssid = re.findall(r"(.*)_([0-9a-f]{12})\.", cracked_file.name)[0]
                with open(cracked_file, 'r') as f:
                    pwd = f.read()
                passwords.append({"ssid": ssid, "bssid": bssid, "password": pwd, "status": status})
            return render_template_string(TEMPLATE, title="Passwords list", passwords=passwords, crack_attempts=self.crack_attempts)
        except Exception as e:
            logging.error(f"[RulesDic] error while updating progress status: {e}")
            logging.debug(e, exc_info=True)

    def check_handcheck(self, filename, interface='wlan0mon'):
        # Ensure the interface is in monitor mode
        check_mode_command = f'iwconfig {interface}'
        mode_check = subprocess.run(check_mode_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        logging.info(f'[RulesDic] iwconfig output: {mode_check.stdout.decode("utf-8")}')
        if b'Monitor' not in mode_check.stdout:
            # If not in monitor mode, set it
            start_monitor_mode = f'sudo airmon-ng start {interface[:-3]}'
            logging.info(f'[RulesDic] Starting monitor mode with command: {start_monitor_mode}')
            subprocess.run(start_monitor_mode, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            # Re-run iwconfig to verify
            mode_check = subprocess.run(check_mode_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            logging.info(f'[RulesDic] iwconfig output after starting monitor mode: {mode_check.stdout.decode("utf-8")}')
        
        command = f'nice /usr/bin/hcxdumptool -i {interface} -o {filename}.pcapng --active_beacon --enable_status=15 --filtermode=2 --disable_deauthentication'
        logging.info(f'[RulesDic] Running hcxdumptool with command: {command}')
        hcxdumptool_execution = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        result = hcxdumptool_execution.stdout.decode('utf-8').strip()
        
        if hcxdumptool_execution.stderr:
            logging.warning(f'[RulesDic] hcxdumptool stderr: {hcxdumptool_execution.stderr.decode("utf-8").strip()}')
        
        for _ in range(3):
            if result:
                break    
            logging.info('[RulesDic] Retry capturing handshake...')
            hcxdumptool_execution = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            result = hcxdumptool_execution.stdout.decode('utf-8').strip()
        
        enhanced_handshake_re = re.compile(
            r'\s+\d+\s+(?P<bssid>([a-fA-F0-9]{2}:){5}[a-fA-F0-9]{2})\s+(?P<ssid>.+?)\s+(?:\([1-9][0-9]* handshake(?:, with PMKID)?\)|\(\d+ handshake(?:, with PMKID)?\)|handshake|PMKID)')
        handshake_match = enhanced_handshake_re.search(result)
        
        if not handshake_match:
            logging.warning('[RulesDic] No handshake found with initial pattern, trying alternative pattern...')
        return handshake_match

    def try_to_crack(self, filename, essid, bssid):
        wordlist_filename = self._generate_dictionnary(filename, essid)
        command = f'nice /usr/bin/hashcat -m 22000 {filename}.pcapng -a 0 -w 3 -o {filename}.cracked {wordlist_filename}'
        logging.info(f'[RulesDic] Running hashcat with command: {command}')  # Log hashcat command
        subprocess.run(command, shell=True, stdout=subprocess.PIPE)
        result = pathlib.Path(f"{filename}.cracked").read_text().strip()

        if result:
            return result.split(':')[1]
        return None

    def _generate_dictionnary(self, filename, essid):
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
        return [essid, essid.upper(), essid.lower(), essid.capitalize(), re.sub('[0-9]*$', "", essid)]

    def _reverse_rule(self, base_essids):
        return [essid[::-1] for essid in base_essids]

    def _punctuation_rule(self, base_essids):
        wd = ["".join(p) for p in product(base_essids, punctuation)]
        wd += ["".join(p) for p in product(base_essids, punctuation, punctuation)]
        wd += ["".join(p) for p in product(punctuation, base_essids)]
        wd += ["".join(p) for p in product(punctuation, base_essids, punctuation)]
        return wd

    def _years_rule(self, base_essids):
        wd = ["".join(p) for p in product(base_essids, self.years)]
        wd += ["".join(p) for p in product(base_essids, self.years, punctuation)]
        wd += ["".join(p) for p in product(base_essids, punctuation, self.years)]
        return wd

    def _leet_rule(self, essid):
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
				passwords = []
				cracked_files = pathlib.Path('/home/pi/handshakes/').glob('*.cracked')
				for cracked_file in cracked_files:
					ssid, bssid = re.findall(r"(.*)_([0-9a-f]{12})\.", cracked_file.name)[0]
					with open(cracked_file, 'r') as f:
						pwd = f.read()
					passwords.append({"ssid": ssid, "bssid": bssid, "password": pwd, "status": status})
				return render_template_string(TEMPLATE, title="Passwords list", passwords=passwords, crack_attempts=self.crack_attempts)
			except Exception as e:
				logging.error(f"[RulesDic] error while updating progress status: {e}")
				logging.debug(e, exc_info=True)			

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)
