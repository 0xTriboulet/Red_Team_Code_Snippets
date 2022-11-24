#!/usr/bin/env python3

__author__ = "0xTriboulet"

with open("dump.txt") as f:
    lines = f.readlines()
    last = lines[-1]
    print("unsigned char cmd[] = ")
    for line in lines:
        new_line = []
        for i in range (0,len(line)-1,2):
            new_line.append("\\x"+line[i:i+2])
        if line is last:
            print('"'+''.join(new_line)+'";')
        else:
            print('"'+''.join(new_line)+'"')
