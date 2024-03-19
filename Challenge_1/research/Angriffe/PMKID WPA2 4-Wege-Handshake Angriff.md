2018 entdeckt.
Angriff setzt an [Robust Security Network Information Element (RSN IE)](Robust%20Security%20Network%20Information%20Element%20(RSN%20IE)) an, ein optionales Feld innerhalb des 802.11 Management Frames.
#### Voraussetzungen:
- **Kein** Client notwendig
- Angreifer muss lediglich einen EAPOL-Frame (Nachricht des 4-Wege-Handshakes) aufzeichnen
- Aufzeichnung enthält Pairwise Master Key Identifier (PMKID)
	`PMKID = HMAC-SHA1-128(PMK, ESSID | BSSID | MAC Client)`
#### Durchführung
1. Verbindung zum AP
	Angreifer erhält in der ersten Handshake-Nachricht den mitgesendeten PMKID. Folgende Parameter werden dadurch bekannt:
	- ESSID
	- BSSID
	- MAC Client
	- PMKID
	Es fehlt somit nur PMK.
	`PMKID = HMAC-SHA1-128(PMK, ESSID | BSSID | MAC Client)`
1. Brute-Force-Angriff auf PMKID
#### Demonstration
[hcxdumptool](hcxdumptool.md)

[Wi-Fi Protected Access 2 (WPA2)](../Wi-Fi%20Protected%20Access%202%20(WPA2).md)

Quelle: https://sarwiki.informatik.hu-berlin.de/WPA2-Angriff
