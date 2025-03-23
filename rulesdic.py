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

def check_handcheck(self, filename, interface='wlan0mon'):
    logging.info('[RulesDic] Checking handshake for filename: %s on interface: %s', filename, interface)
    
    # Ensure the interface is in monitor mode
    if not self._is_monitor_mode(interface):
        self._start_monitor_mode(interface)
    
    command = f'nice /usr/bin/hcxdumptool -i {interface} -o {filename}.pcapng --active_beacon --enable_status=15 --filtermode=2 --disable_deauthentication'
    logging.info(f'[RulesDic] Running hcxdumptool with command: {command}')

    for attempt in range(3):
        result, error = self._run_subprocess(command)
        if result:
            break
        logging.info(f'[RulesDic] Retry capturing handshake... Attempt {attempt + 1}')

    if error:
        logging.warning(f'[RulesDic] hcxdumptool stderr: {error}')
    
    handshake_match = self._parse_handshake(result)
    if not handshake_match:
        logging.warning('[RulesDic] No handshake found with initial pattern')
    return handshake_match

def _is_monitor_mode(self, interface):
    check_mode_command = f'iwconfig {interface}'
    result, _ = self._run_subprocess(check_mode_command)
    logging.info(f'[RulesDic] iwconfig output: {result}')
    return 'Monitor' in result
