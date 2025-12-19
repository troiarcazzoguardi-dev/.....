#!/usr/bin/env bash
set -e

IFACE=${1:-eth0}

echo "[+] Updating system"
sudo apt update && sudo apt upgrade -y

echo "[+] Installing dependencies"
sudo xargs apt install -y < requirements.txt

echo "[+] Building hpingx"
make

echo "[+] Disabling NIC offloads on $IFACE"
sudo ethtool -K $IFACE gro off lro off tso off gso off rx off tx off

echo "[+] Setting hugepages"
echo 512 | sudo tee /proc/sys/vm/nr_hugepages

echo "[+] Stopping irqbalance"
sudo systemctl stop irqbalance || true

echo "[+] Setup completed successfully"
