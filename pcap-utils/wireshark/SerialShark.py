# Original script from https://github.com/spacehuhn/ArduinoPcap
# This version is simplified, turning user inputs into script constants
#
# To use it simply run the following commands:
#  pip3 install --user -r requirements.txt
#  python3 SerialShark.py

# Made by @xdavidhu (github.com/xdavidhu, https://xdavidhu.me/)
import serial
import io
import os
import subprocess
import signal
import time

# Change before running
ESP_USB_PORT = "/dev/ttyUSB0"
ESP_BAUD_RATE = 115200
PIPE_PCAP_FILE = "esp-wifire.pcap"

# Check connection
canBreak = False
while not canBreak:
    try:
        ser = serial.Serial(ESP_USB_PORT, ESP_BAUD_RATE)
        canBreak = True
    except KeyboardInterrupt:
        print("\n[+] Exiting...")
        exit()
    except:
        print("[!] Serial connection failed... Retrying...")
        time.sleep(2)
        continue

print("[+] Serial connected. Name: " + ser.name)

# Open clean file
f = open(PIPE_PCAP_FILE,'wb')

# Wait for transmission begin (usually you must reset the ESP8266)
check = 0
while check == 0:
    line = ser.readline()
    if b"<pcap_pipe>" in line:
        check = 1
        print("[+] Stream started...")

# Start Wireshark PCAP Pipe (Wireshark must be installed of course)
print("[+] Starting up Wireshark...")
cmd = "tail -f -c +0 " + PIPE_PCAP_FILE + " | wireshark -k -i -"
p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True, preexec_fn=os.setsid)

# Keep feeding file from serial outcomes
# Once interrupted kills Wireshark then close file/serial
try:
    while True:
        ch = ser.read()
        f.write(ch)
        f.flush()
except KeyboardInterrupt:
    print("[+] Stopping...")
    os.killpg(os.getpgid(p.pid), signal.SIGTERM)

f.close()
ser.close()
print("[+] Done.")
