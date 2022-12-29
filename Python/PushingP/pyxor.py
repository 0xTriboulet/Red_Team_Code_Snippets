import sys
## by TRIKKSS
def usage():
	print(f"usage: python3 {sys.argv[0]} -c cypher_file -k key -o output")
	exit(1)

if len(sys.argv) != 7:
	usage()

arg_number = 0

for i in range(len(sys.argv)):
	if sys.argv[i] == "-c":
		cypher_file = sys.argv[i+1]
		arg_number += 1
	elif sys.argv[i] == "-o":
		output = sys.argv[i+1]
		arg_number += 1
	elif sys.argv[i] == "-k":
		key = sys.argv[i+1]
		arg_number += 1

if arg_number != 3:
	usage()

try:
	file = open(cypher_file, "rb")
except:
	print("can't open this file")
	exit(1)

output_file = open(output, "wb")

i = 0
while file.peek():
	cypher = ord(file.read(1))
	j = i % len(key)
	k = ord(key[j])
	b = bytes([cypher^k])
	output_file.write(b)
	i += 1