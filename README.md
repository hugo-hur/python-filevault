# python-filevault
Small python project for testing out encryption features of cryptography.py
Currently uses os temporary files to store decrypted files. Can be circumvented by changing file locaation to ramdisk in the future.
On Windows one would need dokany or similar to create a ramdisk. In linux this would be trivial.

Usage: `python fv.py encrypted_filepath [--source path to file/folder to add before opening the vault] [-m move files to vault instead of copying them]`

This opens the vault contents for viewing and adds any files specified in the options to the vault.
You can add files to the vault by moving them into the temp folder that is created while vault is open.

Does not currently support adding folder structures to the encrypted data.

Tested on Windows 10 with Python 3.10.
