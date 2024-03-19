#### Voraussetzungen:
- WPA-PSK
- 4-Wege-Handshake mitschneiden
#### Durchführung
Ermittlung des Passworts über etablierten PTK und MIC (aus 1. oder 2. Nachricht)
1. Information über AP
	- ESSID
	- BSSID
	- Channel
2. 4-Wege-Handshake mitschneiden
	- Deauthentifizierungs-Angriff (kann bemerkt werden)
3. Brute-Force-Angriff auf den mitgeschnittenen 4-Wege-Handshake
	- Folgende Informationen sind durch Handshake bekannt:
		- ANonce
		- SNonce
		- MAC Client
		- BSSID
	- Es fehlt somit nur noch PMK, um PTK zu berechnen.
		- Mit erratenem PMK können die Schlüssel MIC Tx und MIC Rx abgeleitet werden.
		- Anschließen muss MIC über SNonce oder GTK berechnet werden. Stimmt dieser MIC mit dem des 4-Wege-Handshaked überein, wurde der richtige PMK gefunden. (Aus dem PMK kann der PSK berechnet werden)
#### Demonstration mit Tool
[AirCrack](../Tools/AirCrack.md)

#### [Wi-Fi Protected Access 2 (WPA2)](../Wi-Fi%20Protected%20Access%202%20(WPA2).md)



Quelle: https://sarwiki.informatik.hu-berlin.de/WPA2-Angriff