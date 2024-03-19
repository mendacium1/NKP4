WPS wurde 2007 eingeführt, um die Verbindung von Client zum AP für den "Otto-Normal-Verbraucher" zu vereinfachen. In WPS gibt es 3 Modi:

1. PIN: Eingabe 8-stelliger numerischer PIN
2. PBC (Push Button Methode): Drücken eines Knopfes auf beiden Seiten (auf 2 Minuten begrenzt)
3. NFC (Near Field Communication): Client baut Datenverbindung per NFC auf (z.B. bei Druckern) war bei einigen Routern standardmäßig aktiviert

Zunächst war WPS bei vielen Routern standardmäßig aktiviert. Da der PIN-Modus von WPS ist allerdings sehr leicht angreifbar ist, wurde die standardmäßige Aktivierung schon bald wieder rückgängig gemacht. Es ist bekannt, dass der PIN nur aus 8 Zahlen besteht. Zusätzlich bekommt man eine Bestätigung, ob die ersten 4 Ziffern korrekt sind. Die letzte Ziffer ist eine Prüfsumme. Somit braucht man nur `10^4 + 10^3` (also 11000) Kombinationen, um die korrekte PIN zu erraten. Ein Tool, das man für diesen Angriff verwenden kann, ist z. B. Reaver ([https://code.google.com/archive/p/reaver-wps/](https://code.google.com/archive/p/reaver-wps/)).


Quelle: https://sarwiki.informatik.hu-berlin.de/WPA2-Angriff