import crypto
import os
import glob
import argparse
from getpass import getpass


parser = argparse.ArgumentParser()
parser.add_argument("filepath", help="Path to encrypted vault file")
parser.add_argument("--source", help="Adds this file or folder to vault when opening")
parser.add_argument("-m", help="Delete source file after add", action="store_true")
args = parser.parse_args()


fv = None
if not os.path.exists(args.filepath) or os.path.getsize(args.filepath) == 0:
    print("Gotta create new output file!")
    p = getpass("Enter Password: ")
    s = getpass("Enter Salt: ")

    if p != getpass("Enter Password again: ") or s != getpass("Enter Salt again: "):
        print("Passwords or salts do not match!")
        exit(1)

else:
    print("Trying to open existing file")
    p = getpass("Enter Password: ")
    s = getpass("Enter Salt: ")



fv = crypto.filevault(p, s, args.filepath, ciphersuites=["ChaCha20"])

#sourprint(args.source)
#print(args.m)
if args.source != None:
    inputFile = os.path.abspath(args.source)
    if os.path.isdir(inputFile):
        print("Adding all files from directory: " + inputFile)
        files = glob.glob(inputFile + '/**', recursive=True)
        files = [item for item in files if os.path.isfile(item)]

        for fp in files:
            fv.addToVault(fp,move=args.m)
    else:
        print("Adding single file: " + inputFile)
        fv.addToVault(inputFile,move=args.m)

fv.openVault()