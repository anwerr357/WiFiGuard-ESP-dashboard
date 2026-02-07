# WiFiGuard ESP32/ESP8266 - IoT Security Monitor

## 🛡️ Project Overview

This project uses an ESP8266 card to intercept WiFi traffic on your router and send it to a Python Flask server for real-time security analysis. The system detects:

- **DDoS Attacks** (flooding, high traffic concentration)
- **Nmap Port Scans** (network reconnaissance)
- **ARP Spoofing** (man-in-the-middle attacks)
- **MAC Spoofing** (device impersonation)
- **WiFi Pentest Tools** (aireplay-ng, wash, reaver, etc.)
- **Deauthentication Attacks**
- **Unauthorized Devices**

---

## 🔧 Recent Fixes & Improvements

### **1. Fixed False Positive DDoS Detections** ✅

**Problem:** System was flagging normal network traffic as DDoS attacks.

**Old Thresholds (WRONG):**
- 2,000 packets = MEDIUM alert
- 5,000 packets = HIGH alert
- 10,000 packets = CRITICAL alert

**Why this was wrong:** A single device streaming Netflix can generate 5,000-10,000 packets in 20 seconds!

**New Thresholds (CORRECT):**
- 50,000 packets + 40% concentration = MEDIUM alert
- 100,000 packets + 50% concentration = HIGH alert
- 200,000 packets + 60% concentration = CRITICAL alert

**Key Improvement:** Now checks if a **single source** is dominating traffic (concentration %), not just total packet count.

---

### **2. Fixed IP Registration Bug** ✅

**Problem:** IPs were showing as "already registered" then "not registered" randomly.

**Bug Location:** `update_history()` method in Python server

**Original Code (BUGGY):**
```python
if mac not in self.mac_ip_history[mac]:  # WRONG! Checks wrong key
    self.mac_ip_history[mac].append(ip)
```

**Fixed Code:**
```python
if ip not in self.mac_ip_history[mac]:  # CORRECT! Checks if IP in list
    self.mac_ip_history[mac].append(ip)
```

**Result:** IPs and MACs are now properly tracked across scans.

---

### **3. Fixed Distributed DDoS False Positives** ✅

**Problem:** System flagged 3+ devices with >5 ports as "distributed attack"

**Why wrong:** Most computers, smartphones, smart TVs have 5-10 ports open normally!

**Old Logic:**
- 3+ devices with >5 ports = DDoS alert ❌

**New Logic:**
- 5+ devices with >15 ports = DDoS alert ✅

**Reasoning:** Real Nmap scans show 15-20+ ports. Legitimate devices rarely exceed 10-12.

---

### **4. Improved Nmap Scan Detection** ✅

**Changed threshold:** 15 ports → 20 ports

**Why:** 
- Servers, NAS, gaming PCs: 10-15 ports (normal)
- Nmap scans: 20-100+ ports (suspicious)

---

### **5. Enhanced Logging** ✅

**Added detailed DDoS analysis output:**
```
📈 Analyse DDoS:
   - Total paquets: 35,420 (1,771 pkt/s)
   - Source dominante: 23.4% du trafic
   - Seuils: 50k (40%), 100k (50%), 200k (60%)
   ✅ Trafic NORMAL (< 50,000 paquets)
```

This helps you understand **why** traffic is flagged or not.

---

## 📊 Understanding the New Thresholds

### **What is NORMAL traffic?**

| Activity | Packets/20s | Dominant % |
|----------|-------------|------------|
| Web browsing | 500-5,000 | 10-20% |
| YouTube 1080p | 8,000-15,000 | 25-35% |
| Netflix 4K | 15,000-30,000 | 30-45% |
| Large download | 20,000-50,000 | 40-60% |
| **Multiple devices** | 10,000-80,000 | 5-15% each |

### **What is SUSPICIOUS traffic?**

| Attack Type | Packets/20s | Dominant % | Alert |
|-------------|-------------|------------|-------|
| Light flood | 50,000-100,000 | 40-50% | MEDIUM |
| Heavy flood | 100,000-200,000 | 50-60% | HIGH |
| DDoS attack | 200,000+ | 60%+ | CRITICAL |

**Key indicator:** A **single source** generating **>40% of all traffic** with **>50k packets** is suspicious!

---

## 🚀 How to Use

### **1. Hardware Setup**

- ESP8266 or ESP32 board
- WiFi router access
- Python server (PC/laptop on same network)

### **2. Configure ESP8266**

Edit these lines in the `.ino` code:

```cpp
#define SSID "Airbox-1EFD"        // Your WiFi name
#define PASS "J35Y38H8"           // Your WiFi password
#define PC_IP "192.168.1.148"     // Your Python server IP
#define PC_PORT 5000              // Server port
```

### **3. Upload to ESP8266**

1. Open Arduino IDE
2. Install ESP8266 board support
3. Select your board (e.g., NodeMCU 1.0)
4. Upload the code

### **4. Run Python Server**

```bash
cd /home/user/pentest-proxy-esp32/WiFiGuard-ESP
python3 python_p_server.py
```

Server runs on `http://192.168.1.148:5000`

### **5. Access Dashboard**

Open browser: `http://YOUR_SERVER_IP:5000`

You'll see:
- Real-time stats (devices, alerts, traffic)
- Active alerts (current threats)
- Alert history
- Device list with IPs, MACs, ports
- Blacklist management

---

## 🔍 Interpreting Alerts

### **DDoS Alerts**

✅ **SAFE:** < 50,000 packets OR < 40% concentration
⚠️ **MEDIUM:** 50k-100k packets + 40-50% concentration
🔴 **HIGH:** 100k-200k packets + 50-60% concentration
🚨 **CRITICAL:** 200k+ packets + 60%+ concentration

### **Nmap Scan Alerts**

- Device with **20+ open ports** detected
- Check if it's a legitimate server or attacker

### **ARP/MAC Spoofing**

- IP address changed MAC (or vice versa)
- Possible man-in-the-middle attack

### **WiFi Pentest Alerts**

- Deauth frames: aireplay-ng attack
- Beacon flood: MDK3 attack
- WPS probes: Reaver/Wash attack
- EAPOL frames: Handshake capture

---

## 🛠️ Configuration Options

### **Trusted IPs (Python server)**

Edit `TRUSTED_IPS` in `python_p_server.py`:

```python
TRUSTED_IPS = ['192.168.1.179', '192.168.1.1']  # Add your devices
```

Trusted IPs won't trigger Nmap/DDoS alerts.

### **Blacklist IPs**

Use the dashboard to add/remove blacklisted IPs. These will always generate alerts.

### **Alert Expiration**

Alerts expire after **5 minutes** by default:

```python
ALERT_EXPIRATION_MINUTES = 5  # Change this value
```

---

## 📝 Testing Your Setup

### **Test 1: Normal Traffic**

1. Stream YouTube/Netflix
2. Check dashboard - should show < 50k packets ✅
3. No DDoS alerts expected

### **Test 2: High Traffic**

1. Start multiple downloads
2. Open many browser tabs
3. Should see elevated packet count but still < 100k ✅
4. No alerts if traffic is distributed

### **Test 3: Nmap Scan (controlled)**

**⚠️ Only test on YOUR network!**

```bash
nmap -p- 192.168.1.100  # Scan all ports
```

Should trigger: **NMAP_SUSPICIOUS_PORTS** alert ✅

---

## 🐛 Troubleshooting

### **Problem:** Still getting false DDoS alerts

**Solution:** Check the console logs:

```
📈 Analyse DDoS:
   - Total paquets: 65,000
   - Source dominante: 35.2% du trafic
   ✅ Trafic distribué (pas de concentration suspecte)
```

If you see this, it's working correctly! The alert should **NOT** trigger because concentration < 40%.

### **Problem:** IPs not being tracked

**Solution:** Check you applied the `update_history()` fix. Restart the Python server.

### **Problem:** Too many Nmap alerts

**Solution:** Adjust threshold in `detect_nmap_scan()`:

```python
if open_port_count > 25:  # Increase from 20 to 25
```

---

## 📚 Technical Details

### **Packet Capture (ESP8266)**

- Uses promiscuous mode to capture all WiFi packets
- Captures for 20 seconds
- Counts packets per MAC address
- Sends top 10 sources to server

### **Detection Engine (Python)**

- **AttackDetector** class analyzes scan data
- Maintains history of IP/MAC associations
- Compares current scan vs. previous scan
- Generates threat alerts with severity levels

### **Alert System**

- **CRITICAL:** Immediate action required
- **HIGH:** Suspicious, investigate soon
- **MEDIUM:** Monitor, may be normal

---

## 📦 Project Structure

```
WiFiGuard-ESP/
├── projetiot.ino           # ESP8266/ESP32 firmware
├── python_p_server.py      # Python Flask server (FIXED)
├── README.md               # This file
└── esp_webserver           # ESP web interface file
```

---

## 🎯 Future Improvements

- [ ] Machine learning for adaptive thresholds
- [ ] Email/SMS notifications
- [ ] Historical graphs (24hr/7day)
- [ ] Automatic MAC vendor lookup
- [ ] GeoIP location for external IPs
- [ ] Integration with router firewall

---

## ⚖️ Legal Notice

**⚠️ IMPORTANT:** This tool is for **educational purposes** and monitoring **your own network** only.

- ✅ Use on your home/office network
- ✅ Test on devices you own
- ❌ Do NOT use on networks you don't own
- ❌ Do NOT use for malicious purposes

Unauthorized network monitoring may be illegal in your jurisdiction.

---

## 📞 Support

If you encounter issues:

1. Check the console logs (both ESP and Python)
2. Verify IP configuration
3. Ensure ESP and server are on same network
4. Check firewall settings (port 5000)

---

## ✅ Changelog

### v4.1 (Latest)
- ✅ Fixed DDoS false positives (realistic thresholds)
- ✅ Fixed IP registration bug
- ✅ Fixed distributed DDoS detection
- ✅ Improved Nmap detection (20 ports threshold)
- ✅ Enhanced logging with concentration analysis
- ✅ Updated dashboard thresholds

### v4.0
- Initial release with WiFi pentest detection

---

**Made with ❤️ for network security**
