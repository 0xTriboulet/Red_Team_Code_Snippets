#!//bin/python3

import sys
import argparse
import zipfile
import base64
import os
import json

### PARSE ARGS
parser = argparse.ArgumentParser(description=
"smuggler.py ORIGINAL_FILE -i || smuggler.py -o OUTPUT_SUBDIRECTORY")

parser.add_argument("input_file", metavar="ORIGINAL_FILE", nargs="+", help="local input file")

parser.add_argument("-i","--input", help="this is an input operation, will output base64 out.txt from ORIGNAL_FILE", action="store_true")

parser.add_argument("-o","--output", help="this is an output operation, ORIGINAL_FILE from in.txt", action="store_true")

args = parser.parse_args()


### START USING ARGS
if(args.input):
    print("Converting input file:\n* ", args.input_file[0], " --> out.txt")

    ## MAKE TEMP ZIP FILE (OUT.ZIP)
    with zipfile.ZipFile("out.zip", mode="w") as archive:
        archive.write(args.input_file[0])

    ## CONVERT WRITE OUT.ZIP TO OUT.TXT IN BASE64
    with open("out.zip", "rb") as file:                                                    ##OPEN OUT.ZIP
        while(byte := file.read()):                                                        ##READ OUT.ZIP BYTE BY BYTE          
            with open("out.txt", "ab") as out:                                             ##OPEN OUT.TXT
                out.write(base64.b64encode(byte))                                          ##WRITE AS BASE64 BYTES

    ## DELETE OUT.ZIP
    os.remove("out.zip")


### START USING ARGS
if(args.output):
    print("Converting output file:\n* in.txt -->", args.input_file[0])


    ## CONVERT WRITE OUT.ZIP TO OUT.TXT IN BASE64
    with open("in.txt", "r") as file:                                                       ##OPEN IN.ZIP
        while(byte := file.read()):                                                         ##READ IN.ZIP BYTE BY BYTE           
            with open("in.zip", "ab") as into:                                              ##OPEN IN.TXT
                into.write(base64.b64decode(byte))                                          ##WRITE AS BASE64 BYTES
    
    ## MAKE TEMP ZIP FILE (OUT.ZIP)
    with zipfile.ZipFile("in.zip", mode='r') as archive:
        archive.extractall(args.input_file[0])

    ## DELETE OUT.ZIP
    os.remove("in.zip")
