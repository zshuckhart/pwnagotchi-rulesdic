# pwnagotchi-rulesdic
Plugins for pwnagotchi to run aircrack-ng on wordlist based on the ESSID.
For educational purpose only, run it on your OWN WIFI. 

# Install
Aircrack-ng needed, to install:
- apt-get install aircrack-ng
- copy rulesdic.py into your custom plugin directory
- Cracked handshakes stored in handshake folder as [essid].pcap.cracked

Cracked password are also available by click on rulesdic, in the plugin page

# Config.toml
main.plugins.rulesdic.enabled = true
main.plugins.rulesdic.tmp_folder = '/my/tmp/folder' # optional, default: /tmp
main.plugins.rulesdic.max_essid_len = 12 # optional, if set to -1-> no limit else does not general leet rule if len(essid) > max_essid_len
main.plugins.rulesdic.face = '(≡·≡)'

Password wordlist generated:
- Basic: Upper, lower, capitalized, reversed
- Punctuation and years: Adding 1 or 2 puntuation and/or years (1900 until today) in several orders
- Leet: some basic transformations to leet, is len(essid) <= max_essid_len

Based on:
- https://github.com/SilenTree12th/pwnagotchi_plugins/blob/main/better_quickdic.py (main logic)
- https://github.com/xfox64x/pwnagotchi_plugins/blob/master/quick_rides_to_jail/quick_rides_to_jail.py (regexp :-) )
- wpa-sec-list (webhook)

Have fun !
