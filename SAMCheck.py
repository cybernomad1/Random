#!/usr/bin/env python3
import argparse

aparser = argparse.ArgumentParser(description='SAM CHECK', usage="\npython3 SAMCHECK.py -s SAMFile -h Hashes input.nessus")
aparser.add_argument("-s", "--samfile", type=str, nargs='+', help="File contaning active users")
aparser.add_argument("-c", "--crackedhashes", type=str, nargs='+', help="File containing cracked hashes")
args = aparser.parse_args()

sam_file = open(args.samfile[0])
search_sam = []

for login in sam_file:
    search_sam.append(login.strip())

hashes_to_crack = []

hashes_file = open(args.crackedhashes[0])

for hsh in hashes_file:
    hashes = hsh.split(':')
    hash_user = hashes[0].split('\\')
    if len(hash_user) > 1:
        for sam in search_sam:
                if sam == hash_user[1]:
                    print(hsh.rstrip('\n'))
