import binascii
import sys
string = open(sys.argv[1],'r').read()
sys.stdout.write(str(binascii.unhexlify(string))) # needs to be stdout.write to avoid trailing newline
