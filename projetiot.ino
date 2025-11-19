#include <ESP8266WiFi.h>
#include <ESP8266WebServer.h>
#include <WiFiUdp.h> 

// ==================== CONFIGURATION WIFI ====================
const char* ssid = "TT_E710";        
const char* password = "7gfkgc343q"; 

// ==================== SERVEUR WEB ====================
ESP8266WebServer server(80);

// ==================== VARIABLES POUR LE SCAN RÉSEAU ====================
String connectedDevices = "";
int deviceCount = 0;
unsigned long lastScan = 0;
const unsigned long SCAN_INTERVAL = 30000;

// ==================== FONCTION DE SCAN RÉSEAU AMÉLIORÉE ====================
void scanNetwork() {
  Serial.println("🔍 Début du scan réseau avancé...");
  connectedDevices = "";
  deviceCount = 0;
  
  // Obtenir les informations réseau
  IPAddress localIP = WiFi.localIP();
  IPAddress subnet = WiFi.subnetMask();
  IPAddress gateway = WiFi.gatewayIP();
  
  // Calculer la plage réseau
  IPAddress networkAddr = IPAddress(localIP[0] & subnet[0], 
                                   localIP[1] & subnet[1],
                                   localIP[2] & subnet[2],
                                   localIP[3] & subnet[3]);
  
  Serial.print("🌐 Plage réseau: ");
  Serial.print(networkAddr.toString());
  Serial.println(".0/24");
  Serial.print("🔀 Passerelle: ");
  Serial.println(gateway.toString());
  Serial.print("📡 Notre IP: ");
  Serial.println(localIP.toString());
  
  // Liste des appareils détectés
  connectedDevices += "<div style='text-align: left;'>";
  connectedDevices += "<strong>🔀 Passerelle: " + gateway.toString() + "</strong><br>";
  connectedDevices += "<strong>📡 Notre ESP: " + localIP.toString() + "</strong><br><br>";
  
  // Scanner une plage plus large (1-254)
  int devicesFound = 0;
  for (int i = 1; i <= 50; i++) {
    IPAddress targetIP = IPAddress(networkAddr[0], networkAddr[1], networkAddr[2], i);
    
    // Éviter de scanner nous-mêmes et la passerelle dans le comptage
    if (targetIP == localIP || targetIP == gateway) {
      continue;
    }
    
    if (advancedPing(targetIP)) {
      devicesFound++;
      String deviceInfo = "📱 Appareil " + String(devicesFound) + ": " + targetIP.toString();
      connectedDevices += deviceInfo + "<br>";
      Serial.println(deviceInfo);
      
      // Essayer d'obtenir plus d'informations
      String deviceDetails = getDeviceDetails(targetIP);
      if (deviceDetails != "") {
        connectedDevices += "&nbsp;&nbsp;&nbsp;" + deviceDetails + "<br>";
      }
      connectedDevices += "<br>";
    }
    
    // Pause plus courte pour accélérer le scan
    if (i % 10 == 0) delay(30);
  }
  
  deviceCount = devicesFound;
  connectedDevices += "</div>";
  
  Serial.println("✅ Scan terminé - " + String(deviceCount) + " appareils trouvés");
}

// ==================== PING AMÉLIORÉ ====================
bool advancedPing(IPAddress ip) {
  WiFiClient client;
  client.setTimeout(80);
  
  // Plus de ports testés pour une meilleure détection
  int ports[] = {80, 443, 22, 23, 21, 53, 8080, 8000, 3000, 135, 139, 445, 548};
  
  for (int i = 0; i < sizeof(ports)/sizeof(ports[0]); i++) {
    if (client.connect(ip, ports[i])) {
      client.stop();
      return true;
    }
  }
  
  // Essayer également une connexion UDP
  WiFiUDP udp;
  if (udp.begin(1234)) {
    udp.beginPacket(ip, 53);
    udp.write("test");
    if (udp.endPacket()) {
      delay(10);
      udp.stop();
      return true;
    }
    udp.stop();
  }
  
  return false;
}

// ==================== DÉTAILS DE L'APPAREIL ====================
String getDeviceDetails(IPAddress ip) {
  // Tenter d'obtenir le nom NetBIOS (pour les appareils Windows)
  WiFiClient client;
  client.setTimeout(100);
  
  // Essayer le port NetBIOS (139)
  if (client.connect(ip, 139)) {
    client.stop();
    return "Type: Windows/Partage fichier";
  }
  
  // Essayer le port HTTP
  if (client.connect(ip, 80)) {
    client.stop();
    return "Type: Serveur Web";
  }
  
  // Essayer le port SSH
  if (client.connect(ip, 22)) {
    client.stop();
    return "Type: Appareil Linux/SSH";
  }
  
  return "Type: Inconnu";
}

// ==================== PAGE HTML AMÉLIORÉE ====================
String getHTMLPage() {
  String html = R"rawliteral(
<!DOCTYPE HTML>
<html>
<head>
  <title>ESP8266 Network Scanner</title>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <style>
    body { 
      font-family: Arial, sans-serif; 
      margin: 0; 
      padding: 20px; 
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      min-height: 100vh;
    }
    .container { 
      background: white;
      padding: 30px;
      border-radius: 15px;
      box-shadow: 0 10px 30px rgba(0,0,0,0.2);
      max-width: 900px;
      margin: 0 auto;
    }
    .status-card {
      background: #f8f9fa;
      padding: 20px;
      border-radius: 10px;
      margin: 15px 0;
      border-left: 4px solid #28a745;
    }
    .network-card {
      background: #e8f4fd;
      padding: 20px;
      border-radius: 10px;
      margin: 15px 0;
      border-left: 4px solid #17a2b8;
    }
    .devices-card {
      background: #fff3cd;
      padding: 20px;
      border-radius: 10px;
      margin: 15px 0;
      border-left: 4px solid #ffc107;
    }
    .ip-address {
      font-size: 1.5em;
      font-weight: bold;
      color: #007bff;
      margin: 10px 0;
    }
    .device-count {
      font-size: 2em;
      font-weight: bold;
      color: #17a2b8;
      margin: 10px 0;
    }
    .device-list {
      background: white;
      padding: 15px;
      border-radius: 5px;
      margin-top: 10px;
      max-height: 400px;
      overflow-y: auto;
    }
    .last-update {
      margin-top: 20px;
      font-size: 0.9em;
      color: #6c757d;
      text-align: center;
    }
    .btn {
      background: #007bff;
      color: white;
      padding: 10px 20px;
      border: none;
      border-radius: 5px;
      cursor: pointer;
      margin: 5px;
    }
    .btn-scan {
      background: #28a745;
    }
    .btn:hover {
      opacity: 0.8;
    }
    .progress {
      width: 100%;
      background: #f0f0f0;
      border-radius: 5px;
      margin: 10px 0;
    }
    .progress-bar {
      height: 20px;
      background: #007bff;
      border-radius: 5px;
      width: 0%;
      transition: width 0.3s;
    }
  </style>
</head>
<body>
  <div class="container">
    <h1>🛡️ ESP8266 Network Scanner</h1>
    <p>Scanner avancé du réseau WiFi</p>
    
    <div class="status-card">
      <h2>📶 Statut WiFi</h2>
      <div class="ip-address">)rawliteral";
  
  html += WiFi.localIP().toString();
  html += R"rawliteral(</div>
      <div><strong>RSSI:</strong> )rawliteral";
  html += String(WiFi.RSSI());
  html += R"rawliteral( dBm | <strong>Réseau:</strong> )rawliteral";
  html += ssid;
  html += R"rawliteral(</div>
    </div>
    
    <div class="network-card">
      <h2>🌐 Informations Réseau</h2>
      <div><strong>Passerelle:</strong> )rawliteral";
  html += WiFi.gatewayIP().toString();
  html += R"rawliteral(</div>
      <div><strong>Masque:</strong> )rawliteral";
  html += WiFi.subnetMask().toString();
  html += R"rawliteral(</div>
      <div><strong>DNS:</strong> )rawliteral";
  html += WiFi.dnsIP().toString();
  html += R"rawliteral(</div>
    </div>
    
    <div class="devices-card">
      <h2>📱 Appareils Détectés</h2>
      <div class="device-count">)rawliteral";
  
  html += String(deviceCount);
  html += R"rawliteral(</div>
      <div>appareils trouvés sur le réseau local</div>
      
      <div class="progress">
        <div class="progress-bar" id="scanProgress"></div>
      </div>
      
      <div class="device-list" id="deviceList">
        )rawliteral";
  
  html += (connectedDevices == "" ? 
           "<div style='text-align: center; color: #6c757d;'>Aucun scan effectué. Cliquez sur 'Scanner' pour commencer.</div>" : 
           connectedDevices);
  
  html += R"rawliteral(
      </div>
      
      <div style="text-align: center; margin-top: 15px;">
        <button class="btn btn-scan" onclick="startScan()">🔍 Scanner le Réseau</button>
        <button class="btn" onclick="location.reload()">🔄 Actualiser</button>
      </div>
    </div>
    
    <div class="last-update">
      Dernier scan: )rawliteral";
  
  unsigned long uptime = millis() / 1000;
  int hours = uptime / 3600;
  int minutes = (uptime % 3600) / 60;
  int seconds = uptime % 60;
  char timeStr[20];
  sprintf(timeStr, "%02d:%02d:%02d", hours, minutes, seconds);
  html += timeStr;
  
  html += R"rawliteral( | 
      <span id="scanStatus">Prêt</span>
    </div>
  </div>

  <script>
    function startScan() {
      document.getElementById('scanStatus').innerHTML = '⏳ Scanning en cours...';
      document.getElementById('scanProgress').style.width = '0%';
      
      fetch('/scan')
        .then(response => response.text())
        .then(data => {
          // Simuler une progression
          let progress = 0;
          const interval = setInterval(() => {
            progress += 5;
            document.getElementById('scanProgress').style.width = progress + '%';
            if (progress >= 100) {
              clearInterval(interval);
              document.getElementById('scanStatus').innerHTML = '✅ Scan terminé';
              // Recharger après un délai
              setTimeout(() => location.reload(), 1000);
            }
          }, 100);
        })
        .catch(error => {
          document.getElementById('scanStatus').innerHTML = '❌ Erreur de scan';
        });
    }
    
    // Scanner automatiquement au chargement de la page
    window.onload = function() {
      setTimeout(startScan, 1000);
    };
  </script>
</body>
</html>
)rawliteral";

  return html;
}

// ==================== ROUTES DU SERVEUR ====================
void handleRoot() {
  server.send(200, "text/html", getHTMLPage());
}

void handleStatus() {
  String json = "{";
  json += "\"ip\":\"" + WiFi.localIP().toString() + "\",";
  json += "\"gateway\":\"" + WiFi.gatewayIP().toString() + "\",";
  json += "\"ssid\":\"" + String(ssid) + "\",";
  json += "\"rssi\":" + String(WiFi.RSSI()) + ",";
  json += "\"uptime\":" + String(millis() / 1000) + ",";
  json += "\"deviceCount\":" + String(deviceCount);
  json += "}";
  
  server.send(200, "application/json", json);
}

void handleScan() {
  scanNetwork();
  server.send(200, "text/plain", "Scan réseau démarré");
}

// ==================== SETUP ====================
void setup() {
  Serial.begin(115200);
  Serial.println();
  Serial.println("🚀 Démarrage du Network Scanner Avancé...");
  
  WiFi.begin(ssid, password);
  Serial.print("📡 Connexion au WiFi ");
  Serial.print(ssid);
  
  int compteur = 0;
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
    compteur++;
    
    if (compteur > 40) {
      Serial.println();
      Serial.println("❌ Erreur: Impossible de se connecter au WiFi!");
      return;
    }
  }
  
  Serial.println();
  Serial.println("✅ Carte connectée au WiFi!");
  Serial.print("🌐 Adresse IP: ");
  Serial.println(WiFi.localIP());
  Serial.print("🔀 Passerelle: ");
  Serial.println(WiFi.gatewayIP());
  Serial.println("===================================");

  // Configuration du serveur web
  server.on("/", handleRoot);
  server.on("/status", handleStatus);
  server.on("/scan", handleScan);
  
  server.begin();
  Serial.println("🌐 Serveur web démarré!");
  Serial.println("📊 Dashboard: http://" + WiFi.localIP().toString());
}

// ==================== LOOP ====================
void loop() {
  server.handleClient();
  
  // Scan réseau périodique
  if (millis() - lastScan > SCAN_INTERVAL) {
    Serial.println("🔄 Scan réseau périodique...");
    scanNetwork();
    lastScan = millis();
  }
  
  delay(100);
}