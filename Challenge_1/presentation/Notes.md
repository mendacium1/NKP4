## Einfachste Lösung
- Netzwerk auffinden
	- BSSID **(Basic Service Set Identifier)**
		MAC-Adresse Access Point (AP)
	- ESSID **(Extended Service Set Identifier)** oder SSID **(Service Set Identifier)**
		Name eines WLAN-Netzwerks in Klartext
	- "STA (Station) MAC-Adresse" oder "Client MAC-Adresse"
		Mac-Adresse des Clients
- Passiver Scan bis handshake + genug Daten in Scan (Client verbindet sich automatisch immer wieder neu -> kein deauthentication Angriff nötig)
- Handshake mit aircrack-ng oder hashcat bruteforcen -> Netzwerkverkehr nun einsehbar
- dns-querry auffinden
- /etc/hosts editieren oder später auf ip abfragen
	**185.252.72.66 norad.wargames.com**
- GET-request finden und selbst ausführen
	"wget http://norad.wargames.com/wargames_meme_01.png"

## TODO
### pictures
- [ ] airodump-ng (ohne flags)
- [ ] airodump-ng (mit flags)
- [ ] airodump-ng (mit handshake)
- [ ] aircrack-ng (mit wordlist)
- [ ] airdecap-ng (mit password)
- [ ] wireshark (dns)
- [ ] wireshark (http)
- [ ] /etc/hosts
- [ ] wget
- [ ] wargames_meme01.png

## Alternative Lösungen
### Bild aus Netzwerkverkehr extrahieren
wireshark -> dump -> IrfanView
### EvilTwin
EvilTwin aufsetzen und exakten Netzwerkverkehr abfangen

