import sys

try:
    plaintext = open(sys.argv[1], "rb").read()
except:
    print("File argument needed! %s <raw payload file>" % sys.argv[0])
    sys.exit()


open("payload.out",'wb').write(plaintext)
print('unsigned char payload[] = { 0x' + ', 0x'.join(hex(ord(x))[2:] for x in plaintext) + ' };')