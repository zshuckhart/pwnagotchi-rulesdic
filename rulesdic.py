import logging
import os
import re
import subprocess
import resource
import pathlib
from itertools import product
from datetime import datetime
from string import punctuation
from flask import abort, send_from_directory, render_template_string

import pwnagotchi.plugins as plugins
from pwnagotchi.utils import StatusFile
from json.decoder import JSONDecodeError

crackable_handshake_re = re.compile(
    r'\s+\d+\s+(?P<bssid>([a-fA-F0-9]{2}:){5}[a-fA-F0-9]{2})\s+(?P<ssid>.+?)\s+((\([1-9][0-9]* handshake(, with PMKID)?\))|(\(\d+ handshake, with PMKID\)))')

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
        }
        table, th, td {
            border: 1px solid;
            border-collapse: collapse;
        }
        th, td {
            padding: 15px;
            text-align: left;
        }
        @media screen and (max-width:700px) {
            table, tr, td {
                padding:0;
                border:1px solid;
            }
            table {
                border:none;
            }
            tr:first-child, thead, th {
                display:none;
                border:none;
            }
            tr {
                float: left;
                width: 100%;
                margin-bottom: 2em;
            }
            td {
                float: left;
                width: 100%;
                padding:1em;
            }
            td::before {
                content:attr(data-label);
                word-wrap: break-word;
                color: white;
                border-right:2px solid;
                width: 20%;
                float:left;
                padding:1em;
                font-weight: bold;
                margin:-1em 1em -1em -1em;
            }
        }
    </style>
{% endblock %}
{% block script %}
    var searchInput = document.getElementById("searchText");
    searchInput.onkeyup = function() {
        var filter, table, tr, td, i, txtValue;
        filter = searchInput.value.toUpperCase();
        table = document.getElementById("tableOptions");
        if (table) {
            tr = table.getElementsByTagName("tr");

            for (i = 0; i < tr.length; i++) {
                td = tr[i].getElementsByTagName("td")[0];
                if (td) {
                    txtValue = td.textContent || td.innerText;
                    if (txtValue.toUpperCase().indexOf(filter) > -1) {
                        tr[i].style.display = "";
                    }else{
                        tr[i].style.display = "none";
                    }
                }
            }
        }
    }
{% endblock %}
{% block content %}
    <input type="text" id="searchText" placeholder="Search for ..." title="Type in a filter">
    <table id="tableOptions">
        <tr>
            <th>SSID</th>
            <th>BSSID</th>
            <th>Password</th>
        </tr>
        {% for p in passwords %}
            <tr>
                <td data-label="SSID">{{p["ssid"]}}</td>
                <td data-label="BSSID">{{p["bssid"]}}</td>
                <td data-label="Password">{{p["password"]}}</td>
            </tr>
        {% endfor %}
    </table>
{% endblock %}
"""

class RulesDic(plugins.Plugin):
    __authors__ = 'fmatray, awwshucks'
    __version__ = '1.0.2'
    __license__ = 'GPL3'
    __description__ = 'Tries to crack with hashcat with a generated wordlist base on the wifi name'
    __dependencies__ = {
        'apt': ['hashcat'],
    }

    def __init__(self):
        try:
            self.report = StatusFile('/root/handshakes/.rulesdic',
                                     data_format='json')
        except JSONDecodeError:
            os.remove('/root/handshakes/.rulesdic')
            self.report = StatusFile('/root/handshakes/.rulesdic',
                                     data_format='json')

        self.options = dict()
        self.years = list(map(str, range(1900, datetime.now().year + 1)))
        self.years.extend(map(str, range(0, 100)))
        self.running = False
        self.counter = 0

    # called when the plugin is loaded
    def on_loaded(self):
        logging.info('[RulesDic] plugin loaded')

        check = subprocess.run((
            '/usr/bin/dpkg -l hashcat | grep hashcat | awk \'{print $2, $3}\''),
            shell=True, stdout=subprocess.PIPE)
        check = check.stdout.decode('utf-8').strip()
        if check != "hashcat <none>":
            logging.info('[RulesDic] Found %s' % check)
            self.running = True
        else:
            logging.warning('[RulesDic] hashcat is not installed!')

    def on_config_changed(self, config):
        self.options['handshakes'] = config['bettercap']['handshakes']
        if 'exclude' not in self.options:
            self.options['exclude'] = []
        if 'tmp_folder' not in self.options:
            self.options['tmp_folder'] = '/tmp'
        if 'max_essid_len' not in self.options:
            self.options['max_essid_len'] = 12
        if 'face' not in self.options:
            self.options['face'] = '(≡·≡)'

    def on_handshake(self, agent, filename, access_point, client_station):
        if not self.running:
            return

        reported = self.report.data_field_or('reported', default=[])
        excluded = self.report.data_field_or('excluded', default=[])
        essid = os.path.splitext(os.path.basename(filename))[0].split("_")[0]
        if filename in reported:
            logging.info(f'[RulesDic] {filename} already processed')
            return
        if self.options['exclude']:
            if filename in excluded:
                logging.info(f'[RulesDic] {filename} already excluded')
                return
            for pattern in self.options['exclude']:
                if re.match(pattern, essid):
                    excluded.append(filename)
                    self.report.update(data={'reported': reported, 'excluded': excluded})
                    logging.info(f'[RulesDic] {filename} excluded')
                    return
        display = agent.view()
        display.set('face', self.options['face'])
        display.set('status', 'Captured new handshake')
        logging.info(
            f'[RulesDic] New Handshake {filename}')
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
        pwd = self.try_to_crack(filename, essid, bssid)
        duration = (datetime.now() - current_time).total_seconds()
        if not pwd:
            display.set('face', self.options['face'])
            display.set('status', r'Password not found for {essid} :\'()')
            logging.warning(
                f'!!! [RulesDic] !!! Key not found for {essid} in {duration // 60:.0f}min and {duration % 60:.0f}s')
        else:
            display.set('face', self.options['face'])
            display.set('status', r'Password cracked for {essid} :\'()')
            logging.warning(
                f'!!! [RulesDic] !!! Cracked password for {essid}: {pwd}. Found in {duration // 60:.0f}min and {duration % 60:.0f}s')
        reported.append(filename)
        self.report.update(data={'reported': reported, 'excluded': excluded})

    def check_handcheck(self, filename):
        # Run hcxdumptool for a longer duration and with additional options
        hcxdumptool_execution = subprocess.run(
            (f'nice /usr/bin/hcxdumptool -o {filename}.pcapng --active_beacon --enable_status=15 --filtermode=2 --disable_deauthentication'),
            shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        result = hcxdumptool_execution.stdout.decode('utf-8').strip()
        
        # Log the stderr output for debugging purposes
        error_output = hcxdumptool_execution.stderr.decode('utf-8').strip()
        if error_output:
            logging.warning(f'[RulesDic] hcxdumptool stderr: {error_output}')
        
        # Retry mechanism in case of failure
        retries = 3
        while not result and retries > 0:
            logging.info('[RulesDic] Retry capturing handshake...')
            hcxdumptool_execution = subprocess.run(
                (f'nice /usr/bin/hcxdumptool -o {filename}.pcapng --active_beacon --enable_status=15 --filtermode=2 --disable_deauthentication=1'),
                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            result = hcxdumptool_execution.stdout.decode('utf-8').strip()
            retries -= 1
        
        # Use the enhanced regex pattern
        enhanced_handshake_re = re.compile(
            r'\s+\d+\s+(?P<bssid>([a-fA-F0-9]{2}:){5}[a-fA-F0-9]{2})\s+(?P<ssid>.+?)\s+(?:\([1-9][0-9]* handshake(?:, with PMKID)?\)|\(\d+ handshake(?:, with PMKID)?\)|handshake|PMKID)')
        
        handshake_match = enhanced_handshake_re.search(result)
        if not handshake_match:
            logging.warning('[RulesDic] No handshake found with initial pattern, trying alternative pattern...')
            # You can add more alternative patterns here if needed
        
        return handshake_match

    def try_to_crack(self, filename, essid, bssid):
        wordlist_filename = self._generate_dictionnary(filename, essid)
        hashcat_execution = subprocess.run((
            f'nice /usr/bin/hashcat -m 22000 {filename}.pcapng -a 0 -w 3 -o {filename}.cracked {wordlist_filename}'),
            shell=True, stdout=subprocess.PIPE)
        result = pathlib.Path(f"{filename}.cracked").read_text().strip()
        if result:
            return result.split(':')[1]
        return None

    def _generate_dictionnary(self, filename, essid):
        wordlist_filename = os.path.splitext(os.path.basename(filename))[0] + ".txt"
        wordlist_filename = os.path.join(self.options['tmp_folder'], wordlist_filename)
        logging.info(f'[RulesDic] Generating {wordlist_filename}')
        essid_bases = self._essid_base(essid)
        wordlist = essid_bases.copy()
        wordlist.extend(self._reverse_rule(essid_bases))
        wordlist.extend(self._punctuation_rule(essid_bases))
        wordlist.extend(self._years_rule(essid_bases))
        if self.options['max_essid_len'] == -1 or len(essid) <= self.options['max_essid_len']:
            logging.info(f'[RulesDic] Generating leet wordlist')
            wordlist.extend(self._leet_rule(essid))
        wordlist = list(dict.fromkeys(wordlist))
        with open(wordlist_filename, "w") as f:
            f.write('\n'.join(wordlist))
        logging.info(f'[RulesDic] {len(wordlist)} password generated')
        return wordlist_filename

    def _essid_base(self, essid):
        return [essid,
                essid.upper(), essid.lower(), essid.capitalize(),
                re.sub('[0-9]*$', "", essid)]

    def _reverse_rule(self, base_essids):
        return [essid[::-1] for essid in base_essids]

    def _punctuation_rule(self, base_essids):
        wd = ["".join(p) for p in product(base_essids, punctuation)]
        wd.extend(["".join(p) for p in product(base_essids, punctuation, punctuation)])
        wd.extend(["".join(p) for p in product(punctuation, base_essids)])
        wd.extend(["".join(p) for p in product(punctuation, base_essids, punctuation)])
        return wd

    def _years_rule(self, base_essids):
        wd = ["".join(p) for p in product(base_essids, self.years)]
        wd.extend(["".join(p) for p in product(base_essids, self.years, punctuation)])
        wd.extend(["".join(p) for p in product(base_essids, punctuation, self.years)])
        return wd

    def _leet_rule(self, essid):
        # simple leet dictionnary with only simple caracters substitutions
        leet_dict = {
            'a': ['4', '@', 'a', 'A'],
            'b': ['8', '6', 'b', 'B'],
            'c': ['(', '<', '{', '[', 'c', 'C'],
            'd': ['d', 'D'],
            'e': ['3', 'e', 'E'],
            'f': ['f', 'F'],
            'g': ['6', '9', 'g', 'G'],
            'h': ['#', 'h', 'H'],
            'i': ['!', '|', '1', 'i', 'I'],
            'j': ['j', 'J'],
            'k': ['k', 'K'],
            'l': ['1', 'l', 'L'],
            'm': ['m', 'M'],
            'n': ['n', 'N'],
            'o': ['0', 'o', 'O'],
            'p': ['p', 'P'],
            'q': ['q', 'Q'],
            'r': ['r', 'R'],
            's': ['5', '$', 's', 'S'],
            't': ['7', '+', 't', 'T'],
            'u': ['u', 'U'],
            'v': ['v', 'V'],
            'w': ['w', 'W'],
            'x': ['x', 'X'],
            'y': ['y', 'Y'],
            'z': ['2', 'z', 'Z'],
            '0': ['o', 'O', '0'],
            '1': ['i', 'I', '1'],
            '2': ['r', 'R', '2'],
            '3': ['e', 'E', '3'],
            '4': ['a', 'A', '4'],
            '5': ['s', 'S', '5'],
            '6': ['b', 'B', '6'],
            '7': ['y', 'Y', '7'],
            '8': ['b', 'B', '8'],
            '9': ['g', 'G', '9'],
        }
        transformations = [leet_dict.get(c, c) for c in essid.lower()]
        return [''.join(p) for p in product(*transformations)]

    def on_webhook(self, path, request):
        if not self.running:
            return
        if path == "/" or not path:
            try:
                passwords = []
                cracked_files = pathlib.Path('/home/pi/handshakes/').glob(
                    '*.cracked')
                for cracked_file in cracked_files:
                    ssid, bssid = re.findall(r"(.*)_([0-9a-f]{12})\.",
                                             cracked_file.name)[0]
                    with open(cracked_file, 'r') as f:
                        pwd = f.read()
                    passwords.append({
                        "ssid": ssid,
                        "bssid": bssid,
                        "password": pwd})
                return render_template_string(TEMPLATE,
                                              title="Passwords list",
                                              passwords=passwords)
            except Exception as e:
                logging.error(f"[RulesDic] error while loading passwords: {e}")
                logging.debug(e, exc_info=True)
