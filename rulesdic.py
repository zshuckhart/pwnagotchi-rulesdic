import logging
import os
import re
import subprocess
import pathlib
from itertools import product
from datetime import datetime
from string import punctuation
from flask import render_template_string

import pwnagotchi.plugins as plugins
from pwnagotchi.utils import StatusFile
from json.decoder import JSONDecodeError

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
                    if (txtValue.toUpperCase().indexOf(filter) > -1) {
                        tr[i].style.display = '';
                    } else {
                        tr[i].style.display = 'none';
                    }
                }
            }
        }
    }
{% endblock %}
{% block content %}
    <input type="text" id="searchText" placeholder="Search for ..." title="Type in a filter">
    <div id="progressStatus" style="display: none;">
        <p id="progressMessage">Cracking in progress...</p>
    </div>
    <p id="crackAttempts">Handshakes Cracks Attempted: {{ crack_attempts }}</p>
    <table id="tableOptions">
        <tr>
            <th>SSID</th>
            <th>BSSID</th>
            <th>Password</th>
            <th>Status</th>
        </tr>
        {% for p in passwords %}
            <tr>
                <td data-label="SSID">{{p["ssid"]}}</td>
                <td data-label="BSSID">{{p["bssid"]}}</td>
                <td data-label="Password">{{p["password"]}}</td>
                <td data-label="Status">{{p["status"]}}</td>
            </tr>
        {% endfor %}
    </table>
{% endblock %}
"""

# Main plugin class for RulesDic
class RulesDic(plugins.Plugin):
    __authors__ = 'fmatray, awwshucks'
    __version__ = '1.0.2'
    __license__ = 'GPL3'
    __description__ = 'Tries to crack with hashcat with a generated wordlist base on the wifi name'
    __dependencies__ = {
        'apt': ['hashcat'],
    }

    # Initialize the plugin
    def __init__(self):
        self.report = self._load_status_file()
        self.options = self._initialize_options()
        self.years = self._initialize_years()
        self.running = False
        self.counter = 0
        self.crack_attempts = 0  # Add a counter for crack attempts

    # Load the status file or create a new one if it doesn't exist
    def _load_status_file(self):
        try:
            return StatusFile('/root/handshakes/.rulesdic', data_format='json')
        except JSONDecodeError:
            os.remove('/root/handshakes/.rulesdic')
            return StatusFile('/root/handshakes/.rulesdic', data_format='json')

    # Initialize default options for the plugin
    def _initialize_options(self):
        return {'exclude': [], 'tmp_folder': '/tmp', 'max_essid_len': 12, 'face': '(≡·≡)'}

    # Initialize the list of years to be used in the wordlist
    def _initialize_years(self):
        years = list(map(str, range(1900, datetime.now().year + 1)))
        years.extend(map(str, range(0, 100)))
        return years
        
    # Called when the plugin is loaded
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
                logging.error(f'Error: {check.stderr.decode("utf-8 ▋
