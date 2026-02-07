#include <WiFi.h>
#include <WebServer.h>
#include <HTTPClient.h>
#include <esp_wifi.h>

#include <lwip/etharp.h>


// ==================== CONFIGURATION ====================
#define SSID "TOPNET_6D92"
#define PASS "2EHXVNF6YM68"
#define PC_IP "192.168.100.7"
#define PC_PORT 5000

#define MAX_DEVICES 30           //  Reduced for faster scanning
#define ARP_PING_DELAY 10        //  10ms (faster)
#define ARP_WAIT_TIME 2000       //  2000ms (reduced wait)
#define PORT_SCAN_TIMEOUT 150    //  150ms (more reliable)
#define SCAN_PASSES 2            //  2 passes (faster)

// ==================== SERVEUR WEB ====================
WebServer server(80);

// ==================== STRUCTURES ====================
struct Device {
  uint8_t ip;
  uint8_t mac[6];
  uint8_t port;
  char type;
  uint16_t openPorts[10];
  uint8_t openPortCount;
  unsigned long lastSeen;
  uint16_t scanAttempts;
};

struct ARPCache {
  uint8_t ip;
  uint8_t mac[6];
  unsigned long lastSeen;
  bool active;
};

struct PacketSource {
  uint8_t mac[6];
  unsigned long count;
};

// ESP32 uses wifi_promiscuous_pkt_t from esp_wifi.h
// No custom structures needed - using esp_wifi types

// ==================== VARIABLES GLOBALES ====================
Device devices[MAX_DEVICES];
ARPCache arpCache[MAX_DEVICES];
PacketSource topSources[10];

uint8_t deviceCount = 0;
uint8_t cacheSize = 0;
uint8_t topSourceCount = 0;

bool scanning = false;
bool isSniffing = false;
unsigned long scanStartTime = 0;
unsigned long snifferStartTime = 0;

unsigned long totalPacketsCaptured = 0;

// ==================== FONCTIONS HELPER ====================
void IRAM_ATTR trackTopSource(uint8_t *mac) {
  for (uint8_t i = 0; i < topSourceCount; i++) {
    if (memcmp(topSources[i].mac, mac, 6) == 0) {
      topSources[i].count++;
      while (i > 0 && topSources[i].count > topSources[i-1].count) {
        PacketSource temp = topSources[i];
        topSources[i] = topSources[i-1];
        topSources[i-1] = temp;
        i--;
      }
      return;
    }
  }
  
  if (topSourceCount < 10) {
    memcpy(topSources[topSourceCount].mac, mac, 6);
    topSources[topSourceCount].count = 1;
    topSourceCount++;
  } else {
    memcpy(topSources[9].mac, mac, 6);
    topSources[9].count = 1;
  }
}

// ==================== CALLBACK SNIFFER ====================
void IRAM_ATTR packetSnifferCallback(void* buf, wifi_promiscuous_pkt_type_t type) {
  if (!isSniffing) return;

  wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
  uint8_t *packet = pkt->payload;
  uint16_t length = pkt->rx_ctrl.sig_len;

  if (length < 24) return;

  totalPacketsCaptured++;

  uint16_t frameControl = ((uint16_t)packet[1] << 8) | packet[0];
  uint8_t frameType = (frameControl >> 2) & 0x03;
  bool toDS = (frameControl >> 8) & 0x01;
  bool fromDS = (frameControl >> 9) & 0x01;

  uint8_t srcMAC[6];

  if (frameType == 0) {
    memcpy(srcMAC, &packet[10], 6);
  } else if (frameType == 2) {
    if (!toDS && !fromDS) {
      memcpy(srcMAC, &packet[10], 6);
    } else if (toDS && !fromDS) {
      memcpy(srcMAC, &packet[10], 6);
    } else if (!toDS && fromDS) {
      memcpy(srcMAC, &packet[16], 6);
    } else {
      memcpy(srcMAC, &packet[16], 6);
    }
  } else {
    return;
  }

  if ((srcMAC[0] & 0x01) == 0) {
    trackTopSource(srcMAC);
  }
}

// ==================== CACHE ARP ====================
void updateARPCache(uint8_t ip, uint8_t* mac) {
  for (uint8_t i = 0; i < cacheSize; i++) {
    if (arpCache[i].ip == ip) {
      memcpy(arpCache[i].mac, mac, 6);
      arpCache[i].lastSeen = millis();
      arpCache[i].active = true;
      return;
    }
  }
  
  if (cacheSize < MAX_DEVICES) {
    arpCache[cacheSize].ip = ip;
    memcpy(arpCache[cacheSize].mac, mac, 6);
    arpCache[cacheSize].lastSeen = millis();
    arpCache[cacheSize].active = true;
    cacheSize++;
  }
}

void cleanupARPCache() {
  uint8_t newSize = 0;
  unsigned long now = millis();
  
  for (uint8_t i = 0; i < cacheSize; i++) {
    if (arpCache[i].active && (now - arpCache[i].lastSeen) < 300000) {
      if (i != newSize) arpCache[newSize] = arpCache[i];
      newSize++;
    }
  }
  cacheSize = newSize;
}

// ==================== ARP ====================
void arpPing(IPAddress ip) {
  ip4_addr_t ipaddr;
  IP4_ADDR(&ipaddr, ip[0], ip[1], ip[2], ip[3]);
  struct netif *netif = netif_default;
  if (netif != NULL) etharp_request(netif, &ipaddr);
}

bool getARPEntry(IPAddress ip, uint8_t* mac) {
  ip4_addr_t ipaddr;
  IP4_ADDR(&ipaddr, ip[0], ip[1], ip[2], ip[3]);
  
  struct eth_addr* ethAddr = NULL;
  ip4_addr_t* ipRet = NULL;
  struct netif* netif = NULL;
  
  for (int i = 0; i < ARP_TABLE_SIZE; i++) {
    if (etharp_get_entry(i, &ipRet, &netif, &ethAddr) != 0) {
      if (ipRet != NULL && ipRet->addr == ipaddr.addr) {
        if (ethAddr != NULL) {
          memcpy(mac, ethAddr->addr, 6);
          return true;
        }
      }
    }
  }
  return false;
}

// ==================== SCAN PORTS ====================
void scanPortsQuick(IPAddress ip, Device &device) {
  WiFiClient client;
  client.setTimeout(PORT_SCAN_TIMEOUT);
  device.openPortCount = 0;
  device.scanAttempts = 0;
  
  uint16_t ports[] = {80};  // Only scan HTTP to be fast
  
  for (uint8_t i = 0; i < 1; i++) {
    device.scanAttempts++;
    if (client.connect(ip, ports[i])) {
      device.openPorts[device.openPortCount++] = ports[i];
      client.stop();
      delay(3);  // Minimal delay
    }
    yield();
  }
}

char detectDeviceType(IPAddress ip, uint8_t* mac, uint8_t &port) {
  WiFiClient client;
  client.setTimeout(PORT_SCAN_TIMEOUT);
  
  if (client.connect(ip, 80))   { client.stop(); port = 80;   return 'W'; }
  if (client.connect(ip, 443))  { client.stop(); port = 443;  return 'H'; }
  if (client.connect(ip, 8080)) { client.stop(); port = 8080; return 'W'; }
  if (client.connect(ip, 445))  { client.stop(); port = 445;  return 'S'; }
  if (client.connect(ip, 22))   { client.stop(); port = 22;   return 'L'; }
  if (client.connect(ip, 3389)) { client.stop(); port = 3389; return 'R'; }
  
  port = 0;
  return 'U';  // Unknown
}

// ==================== SCAN RÉSEAU OPTIMISÉ ====================
void performScan() {
  if (scanning) return;
  
  scanning = true;
  deviceCount = 0;
  scanStartTime = millis();
  
  Serial.println("\n╔════════════════════════════════════════╗");
  Serial.println("║  SCAN RÉSEAU v5.1 OPTIMISÉ LENT       ║");
  Serial.println("╚════════════════════════════════════════╝");
  
  IPAddress localIP = WiFi.localIP();
  uint8_t base[3] = {localIP[0], localIP[1], localIP[2]};
  
  Serial.printf("📍 Réseau: %d.%d.%d.0/24\n", base[0], base[1], base[2]);
  Serial.printf("📡 ESP IP: %s\n", localIP.toString().c_str());
  Serial.printf("💾 Cache: %d entrées\n\n", cacheSize);
  
  // ========== ÉTAPE 1 : SCAN CACHE ==========
  if (cacheSize > 0) {
    Serial.println("═══ [1/5] 💾 SCAN CACHE ═══");
    for (uint8_t i = 0; i < cacheSize; i++) {
      if (!arpCache[i].active) continue;
      
      IPAddress target(base[0], base[1], base[2], arpCache[i].ip);
      Serial.printf("   Ping cache: %d.%d.%d.%d\n", base[0], base[1], base[2], arpCache[i].ip);
      
      // 3 requêtes ARP (reduced)
      for (uint8_t r = 0; r < 3; r++) {
        arpPing(target);
        delay(10);  // Faster
      }
      yield();
    }
    delay(1000);  // Reduced wait time
    Serial.println("   ✅ Cache scanné\n");
  }
  
  // ========== ÉTAPE 2 : IPS PRIORITAIRES ==========
  Serial.println("═══ [2/5] 🚀 IPS PRIORITAIRES ═══");
  uint8_t priority[] = {1, 254, 14, 7};  
  
  for (uint8_t i = 0; i < sizeof(priority); i++) {
    if (priority[i] == localIP[3]) continue;
    
    IPAddress target(base[0], base[1], base[2], priority[i]);
    Serial.printf("   Ping prioritaire: .%d\n", priority[i]);
    
    // 3 requêtes ARP
    for (uint8_t r = 0; r < 3; r++) {
      arpPing(target);
      delay(ARP_PING_DELAY);
    }
    yield();
  }
  delay(ARP_WAIT_TIME);  // Use configured wait time
  Serial.println("   ✅ IPs prioritaires scannées\n");
  
  // ========== ÉTAPE 3 : SCAN COMPLET MULTI-PASSES ==========
  Serial.printf("═══ [3/5] 📡 SCAN COMPLET (%d passes) ═══\n", SCAN_PASSES);
  
  for (uint8_t pass = 1; pass <= SCAN_PASSES; pass++) {
    Serial.printf("   🔄 Passe %d/%d...\n", pass, SCAN_PASSES);
    
    for (uint8_t i = 1; i <= 254; i++) {
      if (i == localIP[3]) continue;
      
      IPAddress target(base[0], base[1], base[2], i);
      
      // Nombre de pings selon la passe
      uint8_t pings = (pass == 1) ? 3 : 2;
      for (uint8_t p = 0; p < pings; p++) {
        arpPing(target);
        delay(pass == 1 ? 8 : 5);  // Faster scanning
      }
      
      // Pause tous les X IPs
      if (i % 10 == 0) {
        delay(pass == 1 ? 30 : 20);  // Reduced pause
        yield();
      }
    }
    
    // Délai entre passes
    if (pass < SCAN_PASSES) {
      Serial.printf("   ⏳ Attente %dms...\n", pass == 1 ? 1500 : 1000);
      delay(pass == 1 ? 1500 : 1000);  // Reduced inter-pass delay
    }
  }
  Serial.println("   ✅ Scan complet terminé\n");
  
  // ========== ÉTAPE 4 : LECTURE TABLE ARP ==========
  Serial.println("═══ [4/5] 📖 LECTURE ARP + PORTS ═══");
  unsigned long step4Start = millis();
  
  for (uint8_t i = 1; i <= 254 && deviceCount < MAX_DEVICES; i++) {
    if (millis() - step4Start > 5000) {  // Timeout 5s
      Serial.println("   ⚠️ Timeout scan ports! Passage suite...");
      break;
    }
    if (i == localIP[3]) continue;
    
    IPAddress target(base[0], base[1], base[2], i);
    uint8_t mac[6] = {0};
    
    if (getARPEntry(target, mac)) {
      // Vérifier si déjà dans la liste
      bool exists = false;
      for (uint8_t j = 0; j < deviceCount; j++) {
        if (devices[j].ip == i || memcmp(devices[j].mac, mac, 6) == 0) {
          exists = true;
          devices[j].lastSeen = millis();
          break;
        }
      }
      
       if (!exists) {
        uint8_t port;
        char type = detectDeviceType(target, mac, port);
        
        devices[deviceCount].ip = i;
        memcpy(devices[deviceCount].mac, mac, 6);
        devices[deviceCount].port = port;
        devices[deviceCount].type = type;
        devices[deviceCount].lastSeen = millis();
        devices[deviceCount].openPortCount = 0;
        devices[deviceCount].scanAttempts = 0;
        
        scanPortsQuick(target, devices[deviceCount]);
        
        Serial.printf("   ✅ %d.%d.%d.%d | %02X:%02X:%02X:%02X:%02X:%02X | Type:%c | Ports:%d\n",
                      base[0], base[1], base[2], i,
                      mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
                      type, devices[deviceCount].openPortCount);
        
        updateARPCache(i, mac);
        deviceCount++;
      }
    }
    yield();
  }
  
  // ========== ÉTAPE 5 : FINALISATION ==========
  Serial.println("\n═══ [5/5] 🧹 FINALISATION ═══");
  cleanupARPCache();
  
  unsigned long duration = millis() - scanStartTime;
  
  Serial.println("\n╔════════════════════════════════════════╗");
  Serial.printf("║  ✅ SCAN TERMINÉ                       ║\n");
  Serial.println("╠════════════════════════════════════════╣");
  Serial.printf("║  📊 Appareils trouvés: %2d              ║\n", deviceCount);
  Serial.printf("║  ⏱️  Durée: %3lus                       ║\n", duration/1000);
  Serial.printf("║  💾 Cache: %2d entrées                 ║\n", cacheSize);
  Serial.println("╚════════════════════════════════════════╝\n");
  
  scanning = false;
}

// ==================== SNIFFER DDOS ====================
void performDDoSDetection() {
  Serial.println("\n╔════════════════════════════════════╗");
  Serial.println("║   DÉTECTION DDoS (20s)             ║");
  Serial.println("╚════════════════════════════════════╝");

  memset(topSources, 0, sizeof(topSources));
  totalPacketsCaptured = 0;
  topSourceCount = 0;

  Serial.println("⚠️  Déconnexion WiFi...");
  WiFi.disconnect();
  delay(100);

  // Configure ESP32 promiscuous mode
  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  esp_wifi_init(&cfg);
  esp_wifi_set_mode(WIFI_MODE_STA);
  esp_wifi_start();

  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(&packetSnifferCallback);
  esp_wifi_set_channel(1, WIFI_SECOND_CHAN_NONE);

  isSniffing = true;
  snifferStartTime = millis();

  Serial.println("🔍 Capture en cours...");

  // FIX: Sniff ONLY on the connected channel (Router's channel) to catch 100% of traffic
  uint8_t primaryChannel = WiFi.channel();
  if (primaryChannel == 0) primaryChannel = 6; // Default to 6 if unknown
  
  esp_wifi_set_channel(primaryChannel, WIFI_SECOND_CHAN_NONE);
  Serial.printf("🔒 Sniffing locked on Channel %d (Current WiFi)\n", primaryChannel);

  while (millis() - snifferStartTime < 20000) {
    delay(100);
    // No channel hopping - stay focused on the target network
    
    if ((millis() - snifferStartTime) % 2000 < 100) {
       Serial.printf("   📊 %lu paquets capturés...\n", totalPacketsCaptured);
    }
  }

  isSniffing = false;
  esp_wifi_set_promiscuous(false);

  Serial.printf("\n✅ Total: %lu paquets (%lu pkt/s)\n",
                totalPacketsCaptured, totalPacketsCaptured / 20);
  
  if (topSourceCount > 0) {
    Serial.println("\n📡 Top 5 sources:");
    for (uint8_t i = 0; i < topSourceCount && i < 5; i++) {
      String ip = "EXTERNE";
      for (uint8_t j = 0; j < deviceCount; j++) {
        if (memcmp(devices[j].mac, topSources[i].mac, 6) == 0) {
          IPAddress localIP = WiFi.localIP();
          ip = String(localIP[0]) + "." + String(localIP[1]) + "." + 
               String(localIP[2]) + "." + String(devices[j].ip);
          break;
        }
      }
      
      Serial.printf("   %d. %02X:%02X:%02X:%02X:%02X:%02X | %s | %lu pkt (%.1f%%)\n",
                    i+1,
                    topSources[i].mac[0], topSources[i].mac[1], topSources[i].mac[2],
                    topSources[i].mac[3], topSources[i].mac[4], topSources[i].mac[5],
                    ip.c_str(),
                    topSources[i].count,
                    (topSources[i].count * 100.0) / totalPacketsCaptured);
    }
  }
  
  if (totalPacketsCaptured > 100000) {
    Serial.println("\n🚨 ALERTE: Flood DDoS détecté!");
  } else if (totalPacketsCaptured > 50000) {
    Serial.println("\n⚠️  Trafic élevé détecté");
  } else {
    Serial.println("\n✅ Trafic normal");
  }
  
  Serial.println("\n📡 Reconnexion WiFi...");
  WiFi.mode(WIFI_STA);
  WiFi.begin(SSID, PASS);
  
  uint8_t attempts = 0;
  while (WiFi.status() != WL_CONNECTED && attempts < 20) {
    delay(500);
    Serial.print(".");
    attempts++;
  }
  Serial.println(WiFi.status() == WL_CONNECTED ? " ✅" : " ❌");
}

// ==================== JSON ====================
String buildJSON() {
  String json;
  json.reserve(4000);
  
  IPAddress localIP = WiFi.localIP();
  
  json = "{\"esp_ip\":\"" + localIP.toString() + "\",";
  json += "\"scan_duration\":" + String(millis() - scanStartTime) + ",";
  json += "\"timestamp\":" + String(millis()) + ",";
  
  json += "\"ddos_detection\":{";
  json += "\"total_packets\":" + String(totalPacketsCaptured);
  json += ",\"packets_per_sec\":" + String(totalPacketsCaptured / 20);
  json += ",\"capture_duration\":20000";
  json += ",\"top_sources\":[";
  
  for (uint8_t i = 0; i < topSourceCount && i < 10; i++) {
    if (i > 0) json += ",";
    
    String sourceIP = "";
    for (uint8_t j = 0; j < deviceCount; j++) {
      if (memcmp(devices[j].mac, topSources[i].mac, 6) == 0) {
        sourceIP = String(localIP[0]) + "." + String(localIP[1]) + "." + 
                   String(localIP[2]) + "." + String(devices[j].ip);
        break;
      }
    }
    
    json += "{\"mac\":\"";
    for (int j = 0; j < 6; j++) {
      if (topSources[i].mac[j] < 16) json += "0";
      json += String(topSources[i].mac[j], HEX);
      if (j < 5) json += ":";
    }
    json += "\",\"ip\":\"" + sourceIP + "\"";
    json += ",\"packet_count\":" + String(topSources[i].count);
    json += ",\"percentage\":" + String((topSources[i].count * 100.0) / totalPacketsCaptured, 2);
    json += "}";
  }
  json += "]},";
  
  json += "\"devices\":[";
  for (uint8_t i = 0; i < deviceCount; i++) {
    if (i > 0) json += ",";
    json += "{\"ip\":\"" + String(localIP[0]) + "." + String(localIP[1]) + "." + 
            String(localIP[2]) + "." + String(devices[i].ip) + "\",\"mac\":\"";
    for (int j = 0; j < 6; j++) {
      if (devices[i].mac[j] < 16) json += "0";
      json += String(devices[i].mac[j], HEX);
      if (j < 5) json += ":";
    }
    json += "\",\"type\":\"" + String(devices[i].type) + "\"";
    json += ",\"primary_port\":" + String(devices[i].port);
    json += ",\"open_ports\":[";
    for (uint8_t j = 0; j < devices[i].openPortCount; j++) {
      if (j > 0) json += ",";
      json += String(devices[i].openPorts[j]);
    }
    json += "],\"open_port_count\":" + String(devices[i].openPortCount);
    json += ",\"scan_attempts\":" + String(devices[i].scanAttempts);
    json += ",\"last_seen\":" + String(devices[i].lastSeen) + "}";
  }
  json += "]}";
  
  return json;
}

// ==================== ENVOI ====================
void sendScanToPC(String json) {
  if (WiFi.status() != WL_CONNECTED) {
    Serial.println("❌ WiFi non connecté!");
    return;
  }
  
  String url = "http://" + String(PC_IP) + ":" + String(PC_PORT) + "/scan";
  Serial.printf("\n📤 Envoi vers %s\n", url.c_str());
  Serial.printf("   📊 %d devices | %lu packets\n", deviceCount, totalPacketsCaptured);
  
  HTTPClient http;
  WiFiClient client;
  
  http.begin(client, url);
  http.addHeader("Content-Type", "application/json");
  http.setTimeout(15000);
  
  int code = http.POST(json);
  
  if (code > 0) {
    Serial.printf("✅ HTTP %d\n", code);
    if (code == HTTP_CODE_OK || code == HTTP_CODE_CREATED) {
      Serial.println("📥 " + http.getString());
    }
  } else {
    Serial.printf("❌ Erreur HTTP: %s\n", http.errorToString(code).c_str());
  }
  
  http.end();
}

// ==================== HTML ====================
const char HTML_PAGE[] PROGMEM = R"rawliteral(
<!DOCTYPE html>
<html>
<head>
<meta charset='UTF-8'>
<meta name='viewport' content='width=device-width,initial-scale=1'>
<title>ESP DDoS Detector v5.1</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Segoe UI',sans-serif;background:linear-gradient(135deg,#1a1a2e,#16213e,#0f3460,#533483);color:#fff;padding:20px;min-height:100vh}
.container{max-width:900px;margin:0 auto}
.header{text-align:center;margin-bottom:30px;padding:35px;background:linear-gradient(135deg,rgba(239,83,80,0.2),rgba(239,83,80,0.1));border-radius:15px;border:2px solid rgba(239,83,80,0.4);box-shadow:0 10px 40px rgba(0,0,0,0.5)}
h1{background:linear-gradient(135deg,#ef5350,#ff6f00,#ff1744);-webkit-background-clip:text;-webkit-text-fill-color:transparent;font-size:2.5em;font-weight:700;margin-bottom:15px}
.subtitle{color:#ffab91;font-size:1em;margin-bottom:20px}
.device-info{display:flex;justify-content:center;gap:10px;margin-top:15px;flex-wrap:wrap}
.info-badge{background:rgba(30,30,50,0.8);border:1px solid rgba(239,83,80,0.3);padding:8px 15px;border-radius:20px;font-size:0.85em;color:#ffccbc}
.stats{display:grid;grid-template-columns:repeat(3,1fr);gap:20px;margin-bottom:30px}
.stat{background:linear-gradient(135deg,rgba(30,30,50,0.95),rgba(20,20,40,0.9));padding:25px;border-radius:12px;border:1px solid rgba(239,83,80,0.3);text-align:center;transition:all 0.3s}
.stat:hover{transform:translateY(-8px);border-color:rgba(239,83,80,0.6);box-shadow:0 10px 30px rgba(239,83,80,0.3)}
.stat-num{font-size:3em;font-weight:800;color:#00e676;text-shadow:0 0 20px rgba(0,230,118,0.5);margin:15px 0;font-family:'SF Mono',monospace}
.stat-label{color:#b0bec5;font-size:0.9em;text-transform:uppercase;letter-spacing:2px;font-weight:600}
.btn{display:block;width:100%;padding:20px;border:none;border-radius:12px;font-size:1.2em;font-weight:700;cursor:pointer;text-transform:uppercase;letter-spacing:1.5px;transition:all 0.3s;margin-bottom:15px}
.btn:disabled{opacity:0.5;cursor:not-allowed}
.btn-dashboard{background:linear-gradient(135deg,#00e676,#00c853);color:#1a1a2e;box-shadow:0 4px 20px rgba(0,230,118,0.4)}
.btn-dashboard:hover:not(:disabled){transform:translateY(-3px);box-shadow:0 8px 35px rgba(0,230,118,0.8)}
.btn-primary{background:linear-gradient(135deg,#ff1744,#f50057);color:#fff;box-shadow:0 4px 20px rgba(255,23,68,0.4)}
.btn-primary:hover:not(:disabled){transform:translateY(-3px);box-shadow:0 8px 30px rgba(255,23,68,0.6)}
.info-card{background:linear-gradient(135deg,rgba(30,30,50,0.95),rgba(20,20,40,0.9));padding:25px;border-radius:12px;border:1px solid rgba(239,83,80,0.3);margin-bottom:20px}
.info-title{color:#ef5350;font-size:1.3em;font-weight:700;margin-bottom:15px}
.info-item{padding:12px 0;border-bottom:1px solid rgba(255,255,255,0.1);display:flex;justify-content:space-between}
.info-item:last-child{border-bottom:none}
.info-key{color:#b0bec5;font-weight:600}
.info-value{color:#ff5252;font-weight:700;font-family:'SF Mono',monospace}
@media(max-width:768px){.stats{grid-template-columns:1fr}}
</style>
</head>
<body>
<div class='container'>
<div class='header'>
<h1>🛡️ ESP DDoS DETECTOR</h1>
<div class='subtitle'>Scan optimisé v5.1 LENT</div>
<div class='device-info'>
<span class='info-badge'>📡 {{IP}}</span>
<span class='info-badge'>📶 {{RSSI}} dBm</span>
<span class='info-badge'>🔄 Auto 60s</span>
</div>
</div>

<div class='stats'>
<div class='stat'>
<div class='stat-num'>{{DEVICES}}</div>
<div class='stat-label'>Appareils</div>
</div>
<div class='stat'>
<div class='stat-num'>{{PACKETS}}</div>
<div class='stat-label'>Paquets</div>
</div>
<div class='stat'>
<div class='stat-num'>{{CACHE}}</div>
<div class='stat-label'>Cache</div>
</div>
</div>

<button class='btn btn-dashboard' onclick="location.href='http://{{SERVER}}'">
📊 DASHBOARD PYTHON
</button>
<button class='btn btn-primary' onclick='scan()' id='btn'>
🔍 SCAN MANUEL
</button>

<div class='info-card'>
<div class='info-title'>ℹ️ Informations ESP32</div>
<div class='info-item'><span class='info-key'>🌐 IP</span><span class='info-value'>{{IP}}</span></div>
<div class='info-item'><span class='info-key'>📍 Réseau</span><span class='info-value'>{{NETWORK}}.0/24</span></div>
<div class='info-item'><span class='info-key'>🖥️ Serveur</span><span class='info-value'>{{SERVER}}</span></div>
<div class='info-item'><span class='info-key'>⏱️ Dernier scan</span><span class='info-value'>{{DURATION}}s</span></div>
</div>

<div class='info-card'>
<div class='info-title'>🎯 Optimisations v5.1</div>
<div class='info-item'><span class='info-key'>📡 Délai ARP</span><span class='info-value'>15ms (vs 8ms)</span></div>
<div class='info-item'><span class='info-key'>⏳ Attente</span><span class='info-value'>4000ms (vs 2500ms)</span></div>
<div class='info-item'><span class='info-key'>🔄 Passes</span><span class='info-value'>4 passes (vs 3)</span></div>
<div class='info-item'><span class='info-key'>💪 Max devices</span><span class='info-value'>50 (vs 30)</span></div>
</div>
</div>

<script>
function scan(){
const b=document.getElementById('btn');
if(b.disabled)return;
b.disabled=true;
b.textContent='⏳ SCAN LENT (90s)...';
fetch('/scan').then(()=>{
setTimeout(()=>location.reload(),90000);
}).catch(e=>{
alert('❌ Erreur: '+e);
b.disabled=false;
b.textContent='🔍 SCAN MANUEL';
});
}
console.log('🛡️ ESP v5.1 OPTIMISÉ | Scan lent mais complet');
</script>
</body>
</html>
)rawliteral";

String getHTML() {
  String html = FPSTR(HTML_PAGE);
  IPAddress ip = WiFi.localIP();
  String network = String(ip[0]) + "." + String(ip[1]) + "." + String(ip[2]);
  String server = String(PC_IP) + ":" + String(PC_PORT);
  
  html.replace("{{DEVICES}}", String(deviceCount));
  html.replace("{{PACKETS}}", String(totalPacketsCaptured));
  html.replace("{{CACHE}}", String(cacheSize));
  html.replace("{{IP}}", ip.toString());
  html.replace("{{NETWORK}}", network);
  html.replace("{{SERVER}}", server);
  html.replace("{{RSSI}}", String(WiFi.RSSI()));
  html.replace("{{DURATION}}", String((millis() - scanStartTime) / 1000));
  
  return html;
}

// ==================== HANDLERS ====================
void handleRoot() { 
  server.send(200, "text/html", getHTML()); 
}

void handleScan() {
  server.send(200, "text/plain", "Scan en cours");
  performScan();
  performDDoSDetection();
  if (WiFi.status() == WL_CONNECTED) {
    sendScanToPC(buildJSON());
  }
}

// ==================== SETUP ====================
void setup() {
  Serial.begin(115200);
  delay(1000);
  
  Serial.println("\n╔════════════════════════════════════╗");
  Serial.println("║   ESP DDoS DETECTOR v5.1           ║");
  Serial.println("║   SCAN OPTIMISÉ LENT               ║");
  Serial.println("╚════════════════════════════════════╝\n");
  
  WiFi.mode(WIFI_STA);
  WiFi.begin(SSID, PASS);
  
  Serial.print("📡 Connexion WiFi");
  uint8_t tries = 0;
  while (WiFi.status() != WL_CONNECTED && tries < 30) {
    delay(500);
    Serial.print(".");
    tries++;
  }
  Serial.println();
  
  if (WiFi.status() == WL_CONNECTED) {
    Serial.println("✅ WiFi connecté!");
    Serial.printf("📍 IP ESP: %s\n", WiFi.localIP().toString().c_str());
    Serial.printf("📶 Signal: %d dBm\n", WiFi.RSSI());
    Serial.printf("🖥️ Serveur Python: %s:%d\n\n", PC_IP, PC_PORT);
    
    server.on("/", handleRoot);
    server.on("/scan", handleScan);
    server.begin();
    
    Serial.println("🌐 Serveur web actif");
    Serial.println("🔗 http://" + WiFi.localIP().toString() + "\n");
    
    delay(2000);
    
    Serial.println("🚀 Lancement scan initial LENT...\n");
    performScan();
    performDDoSDetection();
    
    if (WiFi.status() == WL_CONNECTED) {
      sendScanToPC(buildJSON());
    }
  } else {
    Serial.println("❌ Connexion WiFi échouée!");
  }
}

// ==================== LOOP ====================
void loop() {
  server.handleClient();
  yield();
  
  static unsigned long lastScan = 0;
  
  if (!scanning && !isSniffing && millis() - lastScan > 60000) {
    lastScan = millis();
    Serial.println("\n⏰ Scan automatique...");
    performScan();
    performDDoSDetection();
    
    if (WiFi.status() == WL_CONNECTED) {
      sendScanToPC(buildJSON());
    } else {
      Serial.println("⚠️ Tentative de reconnexion...");
      WiFi.reconnect();
    }
  }
}