# pwnagotchi-rulesdic
Plugins for pwnagotchi to run hashcat on wordlist based on the ESSID. The main goal is to target weak wifi, like IoT or devices with default passwords.
For educational purpose only, run it on your OWN WIFI. 

# Install
- apt-get install hashcat hcxtools (will download if missing but not recommended)
- copy rulesdic.py into your custom plugin directory
- Cracked handshakes stored in handshake folder as [essid].pcap.cracked

Cracked password are also available by click on rulesdic, in the plugin page

# Config.toml
```
main.plugins.rulesdic.enabled = true
main.plugins.rulesdic.handshake_path = 'my/handhake/folder' # optional, default /home/pi/handshakes
main.plugins.rulesdic.tmp_folder = '/my/tmp/folder' # optional, default: /tmp
main.plugins.rulesdic.max_essid_len = 12 # optional, if set to -1-> no limit else does not general leet rule if len(essid) > max_essid_len
main.plugins.rulesdic.exclude = [  #REGEXP to match the WIFI name
	"^Android",
	"^[Ii][Pp]hone"
]
main.plugins.rulesdic.face = '(≡·≡)'
```
or in new tomlkit format if using
```
[main.plugins.rulesdic]
enabled = true
tmp_folder = '/my/tmp/folder' # optional if not included will default to: /tmp
handshake_path = 'my/handhake/folder' # optional, default /home/pi/handshakes
max_essid_len = 12 # optional, if set to -1-> no limit else does not general leet rule if len(essid) > max_essid_len
exclude = ["^Android", "^[Ii][Pp]hone"] #REGEXP to match the WIFI name
face = '(≡·≡)'
```

Password wordlist generated:
- Basic: Upper, lower, capitalized, reversed
- Punctuation and years: Adding 1 or 2 puntuation and/or years (1900 until today) in several orders
- Leet: some basic transformations to leet, is len(essid) <= max_essid_len

# TODO
- [X] Try with hashcat as it seams more efficient, instead of aircrack-ng.
- [ ] Limit hashcat duration as we don't want to make them run for hours but perhaps 5-10 min max.
- [ ] Improve exclude and add include options to select which wifi to target, perhaps with vendors :-).
- [ ] Add some cool messages and faces on display. It's a bit boring right now.
- [ ] Hack the World!
 
Based on:
- https://github.com/SilenTree12th/pwnagotchi_plugins/blob/main/better_quickdic.py (main logic)
- https://github.com/xfox64x/pwnagotchi_plugins/blob/master/quick_rides_to_jail/quick_rides_to_jail.py (regexp :-) )
- wpa-sec-list (webhook)

Have fun !
