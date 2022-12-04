#!/usr/bin/env python3

__author__ = "0xTriboulet"


import sys
import argparse
import zipfile
import base64
import os
import json
from io import BytesIO
from itertools import cycle

### PARSE ARGS
parser = argparse.ArgumentParser(description=
"smuggler.py ORIGINAL_FILE -i || smuggler.py -o OUTPUT_SUBDIRECTORY")
parser.add_argument("input_file", metavar="ORIGINAL_FILE", nargs="+", help="local input file")
parser.add_argument("-i","--input", help="this is an input operation, will output base64 out.txt from ORIGNAL_FILE", action="store_true")
parser.add_argument("-o","--output", help="this is an output operation, ORIGINAL_FILE from in.txt", action="store_true")

parser.add_argument("-x","--xor", help="this XORs input or output with this value", action="store")
args = parser.parse_args()

## XOR function
def xor(data, key):
    return bytes(a ^ b for a, b in zip(data, cycle(key)))

def make_zip():
    print("Converting input file:\n* ", args.input_file[0], " --> out.txt")
    
    ## MAKE TEMP ZIP FILE (OUT.ZIP)
    with zipfile.ZipFile("out.zip", mode="w") as archive:
        archive.write(args.input_file[0])

    ## CHECK FOR XOR
    if(args.xor):
        with open("out.zip","rb") as i:
            with BytesIO(i.read()) as f:
                encrypted = xor(f.read(),bytes(args.xor,'utf-8'))
                enc_file = open("out_2.zip","ab+")
                enc_file.write(encrypted)
                enc_file.close()

        os.rename("out_2.zip", "out.zip")

    ## CONVERT WRITE OUT.ZIP TO OUT.TXT IN BASE64
    with open("out.zip", "rb") as file:                                                    ##OPEN OUT.ZIP
        while(byte := file.read()):                                                        ##READ OUT.ZIP BYTES
            with open("out.txt", "ab") as out:                                             ##OPEN OUT.TXT
                out.write(base64.b64encode(byte))                                          ##WRITE AS BASE64

    ## DELETE OUT.ZIP
    os.remove("out.zip")

def unmake_zip():
    print("Converting output file:\n* in.txt -->", args.input_file[0])

   ## CONVERT WRITE OUT.ZIP TO OUT.TXT IN BASE64
    with open("in.txt", "r") as file:                                                      ##OPEN IN.ZIP
        while(byte := file.read()):                                                        ##READ IN.ZIP BYTES
            with open("in.zip", "ab") as into:                                             ##OPEN IN.TXT
                into.write(base64.b64decode(byte))                                         ##WRITE AS BYTES

    ## CHECK FOR XOR
    if(args.xor):
        with open("in.zip","rb") as i:
            with BytesIO(i.read()) as f:
                encrypted = xor(f.read(),bytes(args.xor,'utf-8'))
                enc_file = open("in_2.zip","ab+")
                enc_file.write(encrypted)
                enc_file.close()

        os.rename("in_2.zip", "in.zip")

    ## MAKE TEMP ZIP FILE (OUT.ZIP)
    with zipfile.ZipFile("in.zip", mode='r') as archive:
        archive.extractall(args.input_file[0])

    ## DELETE in.ZIP
    os.remove("in.zip")


def main():
    ### START USING ARGS
    if(args.input):
        make_zip()

    ### START USING ARGS
    if(args.output):
        unmake_zip()

main()
