len plaintext 23:
ciphertext 128
22 + 8 + x = 128
x = 97

len plaintext 23:
ciphertext 160
23 + 8 + 97 = 129 (+ 31 padding)

---

Hinsenden 15 Bytes (mit IV xored)
-> bekomme in ersten 16 Bytes im letzten Byte gesuchten Char
-> Referenzwert

Reset IV mit 16 Bytes
Senden 16 Bytes mit letzten Byte brute-force
-> wenn letztes Byte = secret Byte -> gleichen ersten 16 Byte wie referenz