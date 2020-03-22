#!/usr/bin/env bash

echo "[+] Removing old database"
rm -f database.d3v

echo "[+] Downloading new database"
wget https://github.com/d3v1l401/FindCrypt-Ghidra/raw/master/findcrypt_ghidra/database.d3v

echo "[+] Converting database and adding to the plugin"
rm -f FindCrypt/data/database.d3v
python convert_db.py database.d3v FindCrypt/data/database.d3v

echo "[+] Done! Now you can git add the changes!"
