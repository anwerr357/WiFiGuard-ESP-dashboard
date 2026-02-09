# -*- coding: utf-8 -*-
from flask import Flask, request, jsonify, render_template_string
from datetime import datetime, timedelta
from collections import defaultdict, deque
import time

app = Flask(__name__)

# ==================== STOCKAGE DES DONNÉES ====================
scan_history = []
devices_database = {}
alerts = []  # Historique complet
current_alerts = []  # Liste normale au lieu de deque
attack_stats = defaultdict(int)

alert_history = deque(maxlen=50)
device_count_history = deque(maxlen=50)

last_ddos_stats = {
    'total_packets': 0,
    'packets_per_sec': 0,
    'capture_time': 'N/A'
}

current_stats = {
    'total_devices': 0,
    'alert_count': 0,
    'network_packets': 0,
    'packets_per_sec': 0,
    'ddos_count': 0,
    'last_scan': 'Aucun',
    'status': 'SECURE'
}

TRUSTED_IPS = ['192.168.100.7', '192.168.100.1']
TRUSTED_MACS = []
WHITELIST = []
BLACKLIST = []
MAX_HISTORY = 100
ALERT_EXPIRATION_MINUTES = 5

# ==================== CLASSE DE DÉTECTION ====================
class AttackDetector:
    def __init__(self):
        self.previous_scan = {}
        self.mac_ip_history = defaultdict(list)
        self.ip_mac_history = defaultdict(list)
        self.gateway_mac = None
        self.port_scan_history = defaultdict(lambda: {'ports': set(), 'scan_count': 0, 'last_scan': 0})
        self.rapid_port_changes = defaultdict(int)
        
    def analyze(self, scan_data):
        threats = []
        current_devices = scan_data.get('devices', [])
        esp_ip = scan_data.get('esp_ip', '')
        network = '.'.join(esp_ip.split('.')[:3])
        gateway_ip = f"{network}.1"
        
        for device in current_devices:
            ip = device.get('ip', '')
            mac = device.get('mac', '').upper()
            is_trusted = ip in TRUSTED_IPS or mac in TRUSTED_MACS
            open_ports = device.get('open_ports', [])
            open_port_count = device.get('open_port_count', 0)
            
            threats.extend(self.detect_arp_spoofing(ip, mac))
            threats.extend(self.detect_mac_spoofing(ip, mac))
            if ip == gateway_ip:
                threats.extend(self.detect_gateway_spoofing(mac))
            threats.extend(self.detect_unauthorized_device(mac))
            threats.extend(self.detect_blacklisted_device(mac, ip))
            if not is_trusted:
                threats.extend(self.detect_nmap_scan(ip, mac, open_ports, open_port_count))
            self.update_history(ip, mac, open_ports)
        
        threats.extend(self.detect_disappeared_devices(current_devices))
        current_devices_untrusted = [d for d in current_devices if d.get('ip') not in TRUSTED_IPS and d.get('mac', '').upper() not in TRUSTED_MACS]
        threats.extend(self.detect_distributed_ddos(current_devices_untrusted))
        self.previous_scan = {d['ip']: d for d in current_devices}
        return threats
    
    def detect_nmap_scan(self, ip, mac, open_ports, open_port_count):
        threats = []
        # Real Nmap scans typically show 20+ ports open
        # Legitimate servers may have 10-15 ports
        if open_port_count > 20:
            threats.append({
                'type': 'NMAP_SUSPICIOUS_PORTS',
                'severity': 'HIGH',
                'ip': ip,
                'mac': mac,
                'description': f'🔍 Scan Nmap détecté! {ip} a {open_port_count} ports ouverts',
                'details': f'Ports: {", ".join(map(str, open_ports[:10]))}{"..." if len(open_ports) > 10 else ""}',
                'recommendation': 'Activité de scan suspecte - Vérifiez cet appareil.'
            })
        return threats
    
    def detect_distributed_ddos(self, current_devices):
        threats = []
        # Look for devices with suspiciously HIGH port counts (nmap scans)
        # Normal devices have 5-10 ports, scanners have 15+
        suspicious_ips = [d.get('ip', '') for d in current_devices if d.get('open_port_count', 0) > 15]
        
        # Only alert if MANY devices are scanning (distributed attack pattern)
        if len(suspicious_ips) >= 5:
            threats.append({
                'type': 'DDOS_DISTRIBUTED',
                'severity': 'CRITICAL',
                'description': f'🚨 Attaque distribuée détectée!',
                'details': f'{len(suspicious_ips)} appareils avec scans actifs',
                'recommendation': 'Botnet possible - Isolez ces appareils!'
            })
        return threats
    
    def detect_arp_spoofing(self, ip, mac):
        threats = []
        if ip in self.ip_mac_history:
            previous_macs = self.ip_mac_history[ip]
            if mac not in previous_macs and len(previous_macs) > 0:
                threats.append({
                    'type': 'ARP_SPOOFING',
                    'severity': 'CRITICAL',
                    'ip': ip,
                    'mac': mac,
                    'description': f'🚨 ARP Spoofing! {ip} changé',
                    'recommendation': 'MITM possible.'
                })
        return threats
    
    def detect_mac_spoofing(self, ip, mac):
        threats = []
        if mac in self.mac_ip_history:
            previous_ips = self.mac_ip_history[mac]
            if ip not in previous_ips and len(previous_ips) > 0:
                threats.append({
                    'type': 'MAC_SPOOFING',
                    'severity': 'HIGH',
                    'ip': ip,
                    'mac': mac,
                    'description': f'⚠️ MAC Spoofing! {mac}',
                    'recommendation': 'Vérifier.'
                })
        return threats
    
    def detect_gateway_spoofing(self, mac):
        threats = []
        if self.gateway_mac is None:
            self.gateway_mac = mac
        elif self.gateway_mac != mac:
            threats.append({
                'type': 'MITM_GATEWAY',
                'severity': 'CRITICAL',
                'mac': mac,
                'description': f'🔴 MITM Gateway!',
                'recommendation': 'DANGER!'
            })
            self.gateway_mac = mac
        return threats
    
    def detect_unauthorized_device(self, mac):
        threats = []
        if len(WHITELIST) > 0 and mac not in WHITELIST:
            threats.append({
                'type': 'UNAUTHORIZED_DEVICE',
                'severity': 'MEDIUM',
                'mac': mac,
                'description': f'⚡ Non autorisé',
                'recommendation': 'Vérifier.'
            })
        return threats
    
    def detect_blacklisted_device(self, mac, ip):
        threats = []
        if ip in BLACKLIST:
            threats.append({
                'type': 'BLACKLISTED_DEVICE',
                'severity': 'CRITICAL',
                'mac': mac,
                'ip': ip,
                'description': f'🚫 Blacklistée: {ip}',
                'recommendation': 'Bloquer.'
            })
        return threats
    
    def detect_disappeared_devices(self, current_devices):
        threats = []
        current_ips = {d['ip'] for d in current_devices}
        previous_ips = set(self.previous_scan.keys())
        disappeared = previous_ips - current_ips
        if len(disappeared) >= 3:
            threats.append({
                'type': 'DEAUTH_ATTACK',
                'severity': 'HIGH',
                'description': f'⚠️ Deauth! {len(disappeared)} déconnectés',
                'recommendation': 'Vérifier routeur.'
            })
        return threats
    
    def update_history(self, ip, mac, open_ports=None):
        # Track which IPs a MAC has used
        if ip not in self.mac_ip_history[mac]:
            self.mac_ip_history[mac].append(ip)
            if len(self.mac_ip_history[mac]) > 5:
                self.mac_ip_history[mac].pop(0)
        
        # Track which MACs an IP has used  
        if mac not in self.ip_mac_history[ip]:
            self.ip_mac_history[ip].append(mac)
            if len(self.ip_mac_history[ip]) > 5:
                self.ip_mac_history[ip].pop(0)

detector = AttackDetector()

def clean_expired_alerts():
    global current_alerts
    now = datetime.now()
    current_alerts = [
        alert for alert in current_alerts
        if 'timestamp_obj' in alert and (now - alert['timestamp_obj']).total_seconds() < (ALERT_EXPIRATION_MINUTES * 60)
    ]
    print(f"🧹 Nettoyage: {len(current_alerts)} alertes actives")

def update_current_stats():
    global current_stats
    clean_expired_alerts()
    current_stats['total_devices'] = len(devices_database)
    current_stats['alert_count'] = len([a for a in current_alerts if a.get('severity') in ['CRITICAL', 'HIGH']])
    current_stats['network_packets'] = last_ddos_stats.get('total_packets', 0)
    current_stats['packets_per_sec'] = last_ddos_stats.get('packets_per_sec', 0)
    current_stats['ddos_count'] = len([a for a in current_alerts if 'DDOS' in a.get('type', '')])
    current_stats['last_scan'] = scan_history[-1]['timestamp'] if scan_history else 'Aucun'
    current_stats['status'] = 'THREAT' if current_stats['alert_count'] > 0 else 'SECURE'

# ==================== API ====================
@app.route('/api/current_stats')
def get_current_stats():
    clean_expired_alerts()
    update_current_stats()
    return jsonify(current_stats)

@app.route('/api/current_alerts')
def get_current_alerts():
    clean_expired_alerts()
    return jsonify({'alerts': current_alerts})

@app.route('/api/alert_history')
def get_alert_history():
    return jsonify({'alerts': alerts[-100:] if alerts else []})

@app.route('/api/devices')
def get_devices():
    return jsonify({'devices': devices_database})

@app.route('/scan', methods=['POST'])
def receive_scan():
    try:
        global last_ddos_stats, current_alerts
        
        data = request.get_json()
        timestamp_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        timestamp_obj = datetime.now()
        data['timestamp'] = timestamp_str
        
        clean_expired_alerts()
        
        ddos_data = data.get('ddos_detection', {})
        total_packets = ddos_data.get('total_packets', 0)
        packets_per_sec = ddos_data.get('packets_per_sec', 0)
        top_sources = ddos_data.get('top_sources', [])
        
        last_ddos_stats = {
            'total_packets': total_packets,
            'packets_per_sec': packets_per_sec,
            'capture_time': timestamp_str
        }
        
        print(f"\n{'='*60}")
        print(f"📡 SCAN - {timestamp_str}")
        print(f"📊 Appareils: {len(data.get('devices', []))}")
        print(f"🔥 Paquets: {total_packets}")
    
        
        # ========== BUILD MAC TO DEVICE LOOKUP ==========
        # Build MAC to device lookup using full MAC string
        mac_to_device = {}
        for device in data.get('devices', []):
            mac = device.get('mac', '').upper()
            ip = device.get('ip', '')
            if mac and ip:
                mac_to_device[mac] = {'ip': ip, 'mac': mac}
        
        # ========== RESOLVE ALL TOP SOURCES ==========
        resolved_sources = []
        for source in top_sources:
            source_mac = source.get('mac', '').upper()
            source_ip = source.get('ip', '')
            packet_count = source.get('packet_count', 0)
            percentage = (packet_count / total_packets * 100) if total_packets > 0 else 0
            
            source_info = {
                'mac': source_mac,
                'packet_count': packet_count,
                'percentage': percentage,
                'ip': None
            }
            
            # Try to resolve IP: first from ESP's resolution, then from device list
            if source_ip:
                source_info['ip'] = source_ip
            elif source_mac in mac_to_device:
                source_info['ip'] = mac_to_device[source_mac]['ip']
            
            resolved_sources.append(source_info)
        
        # Calculate dominant percentage ONCE
        dominant_percentage = resolved_sources[0]['percentage'] if len(resolved_sources) > 0 else 0
        
        # ========== IDENTIFY SUSPICIOUS SOURCES ==========
        suspicious_sources = [
            s for s in resolved_sources
            if s['ip'] and s['ip'] not in TRUSTED_IPS and s['percentage'] > 10
        ]
        
        high_traffic_sources = [s for s in suspicious_sources if s['percentage'] > 15]
        
        # ========== LOGGING ==========
        print(f"📈 Analyse DDoS:")
        print(f"   - Total paquets: {total_packets:,} ({packets_per_sec:,} pkt/s)")
        print(f"   - Sources résolues: {len(resolved_sources)}")
        print(f"   - Sources suspectes: {len(suspicious_sources)}")
        print(f"   - Source dominante: {dominant_percentage:.1f}% du trafic")
        
        for i, source in enumerate(resolved_sources[:5]):
            resolution_method = ""
            if source['ip']:
                if source['mac'] in mac_to_device:
                    resolution_method = "(device lookup)"
                else:
                    resolution_method = "(ESP IP)"
            else:
                resolution_method = "(unresolved)"
            
            ip_display = source['ip'] if source['ip'] else 'N/A'
            print(f"   - Source #{i+1}: {ip_display} - {source['percentage']:.1f}% {resolution_method}")
        
        if total_packets < 2000:
            print(f"   ✅ Trafic NORMAL (< 2,000 paquets) [MODE TEST]")
        elif dominant_percentage < 30:
            print(f"   ✅ Trafic distribué (pas de concentration suspecte)")
        
        # ========== ALERTES DDoS (SEUILS RÉALISTES) ==========
        ddos_threats = []
        
        # 20 secondes de capture = seuils adaptés au trafic WiFi réel
        # IMPORTANT: L'ESP capture des FRAMES WiFi, pas des paquets TCP/IP individuels
        # - Trafic normal maison: 500-3000 frames (25-150 frames/s)
        # - Streaming/Gaming: 3000-8000 frames (150-400 frames/s)  
        # - Attaque DDoS: >10000 frames (>500 frames/s) avec source dominante
        
        # TIERED DETECTION: Combine volume AND concentration
        if total_packets > 1500 and dominant_percentage > 50 and len(suspicious_sources) > 0:
            # CRITICAL single-source flood
            top_suspicious = suspicious_sources[0]
            threat_data = {
                'type': 'DDOS_NETWORK_FLOOD',
                'severity': 'CRITICAL',
                'description': f'🚨 DDOS FLOOD! {top_suspicious["ip"]} ({top_suspicious["percentage"]:.1f}% du trafic)',
                'details': f'{total_packets:,} frames WiFi ({packets_per_sec:,} frames/s) | Sources suspectes: {", ".join(["{0}({1:.0f}%)".format(s["ip"], s["percentage"]) for s in suspicious_sources[:5]])}',
                'recommendation': '🚨 CRITIQUE! Inondation réseau détectée - Bloquer source immédiatement',
                'ip': top_suspicious['ip'],
                'mac': top_suspicious['mac'],
                'timestamp': timestamp_str,
                'timestamp_obj': timestamp_obj
            }
            ddos_threats.append(threat_data)
        
        elif total_packets > 1500 and len(high_traffic_sources) >= 3:
            # CRITICAL distributed flood
            threat_data = {
                'type': 'DDOS_DISTRIBUTED_FLOOD',
                'severity': 'CRITICAL',
                'description': f'🚨 DDOS DISTRIBUÉ! {len(high_traffic_sources)} sources actives',
                'details': f'{total_packets:,} frames WiFi | Sources: {", ".join(["{0}({1:.0f}%)".format(s["ip"], s["percentage"]) for s in high_traffic_sources])}',
                'recommendation': '🚨 CRITIQUE! Attaque distribuée - Plusieurs sources malveillantes',
                'timestamp': timestamp_str,
                'timestamp_obj': timestamp_obj
            }
            # high_traffic_sources always has IPs (filtered from suspicious_sources which requires IP)
            threat_data['ip'] = high_traffic_sources[0]['ip']
            threat_data['mac'] = high_traffic_sources[0]['mac']
            ddos_threats.append(threat_data)
        
        elif total_packets > 1200 and dominant_percentage > 40 and len(suspicious_sources) > 0:
            # HIGH traffic
            top_suspicious = suspicious_sources[0]
            threat_data = {
                'type': 'DDOS_HIGH_TRAFFIC',
                'severity': 'HIGH',
                'description': f'⚠️ Trafic élevé suspect - {top_suspicious["ip"]} ({top_suspicious["percentage"]:.1f}%)',
                'details': f'{total_packets:,} frames WiFi ({packets_per_sec:,} frames/s)',
                'recommendation': '⚠️ Surveiller - Concentration anormale détectée',
                'ip': top_suspicious['ip'],
                'mac': top_suspicious['mac'],
                'timestamp': timestamp_str,
                'timestamp_obj': timestamp_obj
            }
            ddos_threats.append(threat_data)
        
        elif total_packets > 1000 and dominant_percentage > 30 and len(suspicious_sources) > 0:
            # MEDIUM traffic
            top_suspicious = suspicious_sources[0]
            threat_data = {
                'type': 'DDOS_MODERATE_TRAFFIC',
                'severity': 'MEDIUM',
                'description': f'ℹ️ Trafic concentré - {top_suspicious["ip"]} ({top_suspicious["percentage"]:.1f}%)',
                'details': f'{total_packets:,} frames WiFi ({dominant_percentage:.1f}% d\'une source)',
                'recommendation': 'ℹ️ Trafic à surveiller - Concentration modérée',
                'ip': top_suspicious['ip'],
                'mac': top_suspicious['mac'],
                'timestamp': timestamp_str,
                'timestamp_obj': timestamp_obj
            }
            ddos_threats.append(threat_data)
        
        elif total_packets > 1500 and dominant_percentage < 30 and len(resolved_sources) > 0:
            # High volume but evenly distributed - no alert
            print(f"   ℹ️ Volume élevé mais trafic distribué uniformément, probablement normal")
        
        current_alerts = [a for a in current_alerts if 'DDOS' not in a.get('type', '')]
        
        for threat in ddos_threats:
            alerts.append(threat)
            current_alerts.append(threat)
            attack_stats[threat['type']] += 1
        
        
        # ========== ANALYSE NORMALE ==========
        threats = detector.analyze(data)
        for threat in threats:
            threat['timestamp'] = timestamp_str
            threat['timestamp_obj'] = timestamp_obj
            alerts.append(threat)
            
            is_duplicate = any(
                a.get('type') == threat['type'] and 
                a.get('ip') == threat.get('ip') 
                for a in current_alerts
            )
            if not is_duplicate:
                current_alerts.append(threat)
        
        if len(alerts) > 200:
            alerts[:] = alerts[-200:]
        
        critical_alerts = len([t for t in threats + ddos_threats if t['severity'] in ['CRITICAL', 'HIGH']])
        alert_history.append({'timestamp': timestamp_str, 'count': critical_alerts})
        device_count_history.append({'timestamp': timestamp_str, 'count': len(data.get('devices', []))})
        
        scan_history.append(data)
        if len(scan_history) > MAX_HISTORY:
            scan_history.pop(0)
        
        for device in data.get('devices', []):
            mac = device.get('mac', '').upper()
            if mac:
                if mac not in devices_database:
                    devices_database[mac] = {
                        'first_seen': timestamp_str,
                        'ips': [],
                        'type': device.get('type', 'U'),
                        'open_ports': []
                    }
                ip = device.get('ip', '')
                if ip and ip not in devices_database[mac]['ips']:
                    devices_database[mac]['ips'].append(ip)
                devices_database[mac]['open_ports'] = device.get('open_ports', [])
        
        update_current_stats()
        
        print(f"✅ Menaces totales: {len(threats) + len(ddos_threats) }")
        print(f"   - DDoS: {len(ddos_threats)}")
        print(f"   - Autres: {len(threats)}")
        print(f"🔥 Alertes actives: {len(current_alerts)}")
        print(f"{'='*60}\n")
        
        return jsonify({'status': 'success'}), 200
    except Exception as e:
        import traceback
        print(f"❌ Erreur: {str(e)}")
        print(traceback.format_exc())
        return jsonify({'status': 'error', 'message': str(e)}), 400

@app.route('/api/activity')
def get_activity():
    return jsonify({'alerts': list(alert_history), 'devices': list(device_count_history)})

@app.route('/api/blacklist', methods=['GET'])
def get_blacklist():
    return jsonify({'blacklist': BLACKLIST})

@app.route('/api/blacklist/add', methods=['POST'])
def add_to_blacklist():
    try:
        data = request.get_json()
        ip = data.get('ip', '').strip()
        if not ip:
            return jsonify({'status': 'error', 'message': 'IP vide'}), 400
        parts = ip.split('.')
        if len(parts) != 4 or not all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
            return jsonify({'status': 'error', 'message': 'Format invalide'}), 400
        if ip in BLACKLIST:
            return jsonify({'status': 'error', 'message': 'Déjà blacklistée'}), 400
        if ip in TRUSTED_IPS:
            return jsonify({'status': 'error', 'message': 'IP de confiance'}), 400
        BLACKLIST.append(ip)
        return jsonify({'status': 'success', 'blacklist': BLACKLIST})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/blacklist/remove', methods=['POST'])
def remove_from_blacklist():
    try:
        data = request.get_json()
        ip = data.get('ip', '').strip()
        if ip not in BLACKLIST:
            return jsonify({'status': 'error', 'message': 'Non trouvée'}), 404
        BLACKLIST.remove(ip)
        return jsonify({'status': 'success', 'blacklist': BLACKLIST})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/clear_alerts', methods=['POST'])
def clear_alerts_route():
    global alerts, attack_stats, current_alerts
    alerts = []
    current_alerts = []
    attack_stats = defaultdict(int)
    update_current_stats()
    return jsonify({'status': 'success'})

@app.route('/')
def dashboard():
    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>WiFi Security Monitor v4.0</title>
        <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body {
                font-family: 'Inter', -apple-system, sans-serif;
                background: linear-gradient(135deg, #1a1a2e, #16213e, #0f3460, #533483);
                color: #fff;
                min-height: 100vh;
                overflow-x: hidden;
            }
            
            .history-sidebar {
                position: fixed;
                top: 0;
                right: -450px;
                width: 450px;
                height: 100vh;
                background: linear-gradient(135deg, rgba(20, 20, 35, 0.98), rgba(15, 15, 25, 0.98));
                backdrop-filter: blur(20px);
                box-shadow: -5px 0 30px rgba(0,0,0,0.5);
                transition: right 0.4s cubic-bezier(0.68, -0.55, 0.265, 1.55);
                z-index: 2000;
                display: flex;
                flex-direction: column;
                border-left: 2px solid rgba(239, 83, 80, 0.3);
            }
            .history-sidebar.open { right: 0; }
            .sidebar-header {
                padding: 25px;
                border-bottom: 2px solid rgba(239, 83, 80, 0.3);
                display: flex;
                justify-content: space-between;
                align-items: center;
                background: rgba(239, 83, 80, 0.1);
            }
            .sidebar-title {
                font-size: 1.4em;
                font-weight: 700;
                color: #ef5350;
                display: flex;
                align-items: center;
                gap: 10px;
            }
            .close-sidebar {
                background: rgba(255, 23, 68, 0.2);
                border: 2px solid rgba(255, 23, 68, 0.4);
                color: #ff5252;
                border-radius: 8px;
                padding: 8px 16px;
                cursor: pointer;
                font-weight: 700;
                transition: all 0.3s;
            }
            .close-sidebar:hover {
                background: rgba(255, 23, 68, 0.4);
                transform: scale(1.05);
            }
            .sidebar-content {
                flex: 1;
                overflow-y: auto;
                padding: 20px;
            }
            .history-alert {
                background: rgba(30, 30, 50, 0.6);
                padding: 15px;
                margin: 12px 0;
                border-radius: 8px;
                border-left: 4px solid;
                transition: all 0.3s;
            }
            .history-alert:hover {
                background: rgba(30, 30, 50, 0.9);
                transform: translateX(-5px);
            }
            .history-alert.critical { border-color: #ff1744; }
            .history-alert.high { border-color: #ff6f00; }
            .history-alert.medium { border-color: #ffab00; }
            
            .history-toggle-btn {
                position: fixed;
                top: 20px;
                right: 20px;
                background: linear-gradient(135deg, #ff1744, #f50057);
                color: white;
                border: none;
                padding: 12px 20px;
                border-radius: 8px;
                font-weight: 700;
                cursor: pointer;
                z-index: 1999;
                box-shadow: 0 4px 15px rgba(255, 23, 68, 0.4);
                transition: all 0.3s;
                display: flex;
                align-items: center;
                gap: 8px;
            }
            .history-toggle-btn:hover {
                transform: translateY(-2px);
                box-shadow: 0 6px 20px rgba(255, 23, 68, 0.6);
            }
            .history-badge {
                background: #fff;
                color: #ff1744;
                padding: 2px 8px;
                border-radius: 12px;
                font-size: 0.85em;
                font-weight: 800;
            }
            
            .container {
                max-width: 1800px;
                margin: 0 auto;
                padding: 20px;
                position: relative;
                z-index: 1;
            }
            
            .header {
                text-align: center;
                margin-bottom: 30px;
                padding: 30px;
                background: linear-gradient(135deg, rgba(30, 30, 50, 0.95), rgba(20, 20, 40, 0.9));
                border-radius: 12px;
                backdrop-filter: blur(15px);
                box-shadow: 0 8px 32px rgba(0, 0, 0, 0.4);
                border: 1px solid rgba(239, 83, 80, 0.2);
            }
            
            .main-title {
                font-size: 2.5em;
                font-weight: 700;
                margin-bottom: 15px;
                background: linear-gradient(135deg, #ef5350, #ff6f00, #ff1744);
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
                letter-spacing: -0.5px;
            }
            
            .detection-list {
                display: flex;
                flex-wrap: wrap;
                justify-content: center;
                gap: 8px;
                margin-top: 15px;
            }
            
            .detection-badge {
                padding: 6px 14px;
                background: rgba(239, 83, 80, 0.15);
                border: 1px solid rgba(239, 83, 80, 0.3);
                border-radius: 20px;
                font-size: 0.75em;
                font-weight: 600;
                text-transform: uppercase;
                letter-spacing: 0.5px;
                color: #ffccbc;
            }
            
            .stats-grid {
                display: grid;
                grid-template-columns: repeat(6, 1fr);
                gap: 15px;
                margin-bottom: 30px;
            }
            
            .stat-card {
                background: linear-gradient(135deg, rgba(30, 30, 50, 0.95), rgba(20, 20, 40, 0.9));
                padding: 20px;
                border-radius: 10px;
                border: 1px solid rgba(239, 83, 80, 0.2);
                backdrop-filter: blur(10px);
                text-align: center;
                transition: all 0.3s;
                box-shadow: 0 4px 15px rgba(0, 0, 0, 0.3);
                position: relative;
            }
            
            @keyframes updatePulse {
                0%, 100% { 
                    border-color: rgba(239, 83, 80, 0.2);
                    box-shadow: 0 4px 15px rgba(0, 0, 0, 0.3);
                }
                50% { 
                    border-color: rgba(239, 83, 80, 0.6);
                    box-shadow: 0 8px 25px rgba(239, 83, 80, 0.3);
                }
            }
            
            .stat-card.updating {
                animation: updatePulse 0.8s ease-in-out;
            }
            
            .stat-card:hover {
                transform: translateY(-5px);
                border-color: rgba(239, 83, 80, 0.5);
                box-shadow: 0 8px 25px rgba(239, 83, 80, 0.3);
            }
            
            .stat-label {
                color: #b0bec5;
                font-size: 0.75em;
                text-transform: uppercase;
                letter-spacing: 1px;
                font-weight: 700;
                margin-bottom: 12px;
            }
            
            .stat-number {
                font-size: 2.8em;
                font-weight: 800;
                margin: 10px 0;
                line-height: 1;
                font-family: 'SF Mono', monospace;
                transition: all 0.3s;
            }
            
            .stat-sublabel {
                color: #78909c;
                font-size: 0.7em;
                margin-top: 8px;
            }
            
            .critical { color: #ff1744; text-shadow: 0 0 20px rgba(255, 23, 68, 0.5); }
            .high { color: #ff6f00; text-shadow: 0 0 15px rgba(255, 111, 0, 0.5); }
            .safe { color: #00e676; text-shadow: 0 0 15px rgba(0, 230, 118, 0.5); }
            .neutral { color: #78909c; }
            
            .status-badge {
                padding: 10px 22px;
                border-radius: 6px;
                font-weight: 700;
                font-size: 1em;
                text-transform: uppercase;
                letter-spacing: 1px;
                font-family: 'SF Mono', monospace;
                transition: all 0.3s;
            }
            
            .status-safe {
                background: rgba(0, 230, 118, 0.15);
                color: #00e676;
                border: 2px solid #00e676;
                box-shadow: 0 0 20px rgba(0, 230, 118, 0.3);
            }
            
            .status-danger {
                background: rgba(255, 23, 68, 0.15);
                color: #ff1744;
                border: 2px solid #ff1744;
                box-shadow: 0 0 20px rgba(255, 23, 68, 0.3);
                animation: pulse 2s infinite;
            }
            
            @keyframes pulse {
                0%, 100% { box-shadow: 0 0 20px rgba(255, 23, 68, 0.3); }
                50% { box-shadow: 0 0 30px rgba(255, 23, 68, 0.6); }
            }
            
            .live-indicator {
                position: absolute;
                top: 10px;
                right: 10px;
                width: 8px;
                height: 8px;
                background: #00e676;
                border-radius: 50%;
                box-shadow: 0 0 10px #00e676;
                animation: blink 2s infinite;
            }
            
            @keyframes blink {
                0%, 100% { opacity: 1; }
                50% { opacity: 0.3; }
            }
            
            .chart-section {
                background: linear-gradient(135deg, rgba(30, 30, 50, 0.95), rgba(20, 20, 40, 0.9));
                padding: 30px;
                border-radius: 12px;
                border: 1px solid rgba(239, 83, 80, 0.2);
                backdrop-filter: blur(10px);
                margin-bottom: 30px;
                box-shadow: 0 8px 32px rgba(0, 0, 0, 0.4);
            }
            
            .chart-title {
                font-size: 1.5em;
                font-weight: 700;
                margin-bottom: 20px;
            }
            
            .chart-container {
                position: relative;
                height: 350px;
            }
            
            .section {
                background: linear-gradient(135deg, rgba(30, 30, 50, 0.95), rgba(20, 20, 40, 0.9));
                padding: 30px;
                border-radius: 12px;
                border: 1px solid rgba(239, 83, 80, 0.2);
                backdrop-filter: blur(10px);
                margin-bottom: 30px;
                box-shadow: 0 8px 32px rgba(0, 0, 0, 0.4);
            }
            
            .section-header {
                display: flex;
                justify-content: space-between;
                align-items: center;
                margin-bottom: 25px;
                padding-bottom: 15px;
                border-bottom: 1px solid rgba(239, 83, 80, 0.2);
            }
            
            h2 {
                font-size: 1.5em;
                font-weight: 700;
            }
            
            .section-count {
                background: rgba(239, 83, 80, 0.2);
                border: 1px solid rgba(239, 83, 80, 0.3);
                padding: 5px 15px;
                border-radius: 20px;
                font-weight: 700;
                color: #ff5252;
                transition: all 0.3s;
            }
            
            .alert {
                padding: 20px;
                margin: 15px 0;
                border-radius: 8px;
                border-left: 4px solid;
                background: rgba(30, 30, 50, 0.5);
                transition: all 0.3s;
            }
            
            .alert:hover {
                transform: translateX(5px);
                background: rgba(30, 30, 50, 0.7);
            }
            
            .alert-critical { border-color: #ff1744; }
            .alert-high { border-color: #ff6f00; }
            .alert-medium { border-color: #ffab00; }
            
            .alert-header {
                display: flex;
                justify-content: space-between;
                margin-bottom: 12px;
            }
            
            .alert-title {
                font-weight: 600;
                font-size: 1.05em;
                flex: 1;
            }
            
            .alert-details {
                color: #b0bec5;
                margin: 8px 0;
                font-size: 0.9em;
                line-height: 1.6;
            }
            
            .alert-tool {
                display: inline-block;
                background: rgba(255, 152, 0, 0.2);
                border: 1px solid rgba(255, 152, 0, 0.4);
                color: #ffa726;
                padding: 4px 10px;
                border-radius: 4px;
                font-size: 0.75em;
                font-weight: 700;
                margin-top: 8px;
                font-family: 'SF Mono', monospace;
            }
            
            .badge {
                display: inline-block;
                padding: 4px 12px;
                border-radius: 4px;
                font-size: 0.7em;
                font-weight: 700;
                text-transform: uppercase;
            }
            
            .badge-critical { background: #ff1744; color: white; }
            .badge-high { background: #ff6f00; color: white; }
            .badge-medium { background: #ffab00; color: black; }
            
            .blacklist-form {
                display: flex;
                gap: 10px;
                margin-bottom: 20px;
            }
            
            .blacklist-input {
                flex: 1;
                padding: 12px 18px;
                background: rgba(30, 30, 50, 0.6);
                border: 2px solid rgba(239, 83, 80, 0.3);
                border-radius: 8px;
                color: #fff;
                font-size: 0.95em;
                font-family: 'SF Mono', monospace;
                transition: all 0.3s;
            }
            
            .blacklist-input:focus {
                outline: none;
                border-color: rgba(239, 83, 80, 0.6);
                background: rgba(30, 30, 50, 0.8);
            }
            
            .blacklist-input::placeholder {
                color: #78909c;
            }
            
            .blacklist-btn {
                padding: 12px 24px;
                background: linear-gradient(135deg, #ff1744, #f50057);
                color: white;
                border: none;
                border-radius: 8px;
                font-size: 0.9em;
                font-weight: 700;
                cursor: pointer;
                transition: all 0.3s;
                text-transform: uppercase;
                letter-spacing: 1px;
            }
            
            .blacklist-btn:hover {
                transform: translateY(-2px);
                box-shadow: 0 6px 20px rgba(255, 23, 68, 0.5);
            }
            
            .blacklist-item {
                display: flex;
                justify-content: space-between;
                align-items: center;
                background: rgba(30, 30, 50, 0.5);
                padding: 15px;
                margin: 10px 0;
                border-radius: 8px;
                border-left: 3px solid #ff1744;
                transition: all 0.3s;
            }
            
            .blacklist-item:hover {
                transform: translateX(5px);
                background: rgba(30, 30, 50, 0.7);
            }
            
            .blacklist-ip {
                font-family: 'SF Mono', monospace;
                font-weight: 700;
                color: #ff5252;
                font-size: 1.1em;
            }
            
            .remove-btn {
                padding: 8px 16px;
                background: rgba(255, 23, 68, 0.2);
                border: 1px solid rgba(255, 23, 68, 0.4);
                border-radius: 6px;
                color: #ff5252;
                font-size: 0.85em;
                font-weight: 600;
                cursor: pointer;
                transition: all 0.3s;
            }
            
            .remove-btn:hover {
                background: rgba(255, 23, 68, 0.3);
                border-color: rgba(255, 23, 68, 0.6);
            }
            
            .device-item {
                display: flex;
                justify-content: space-between;
                align-items: center;
                background: rgba(30, 30, 50, 0.5);
                padding: 18px;
                margin: 12px 0;
                border-radius: 8px;
                border-left: 3px solid #ef5350;
                transition: all 0.3s;
            }
            
            .device-item:hover {
                transform: translateX(5px);
                background: rgba(30, 30, 50, 0.7);
                border-color: #ff1744;
            }
            
            .device-main { flex: 1; }
            
            .device-mac {
                font-family: 'SF Mono', monospace;
                font-weight: 700;
                color: #ff5252;
                font-size: 1em;
                margin-bottom: 8px;
            }
            
            .device-details {
                color: #b0bec5;
                font-size: 0.85em;
                display: flex;
                gap: 15px;
                flex-wrap: wrap;
            }
            
            .device-detail {
                display: flex;
                align-items: center;
                gap: 5px;
            }
            
            .empty-state {
                text-align: center;
                padding: 60px 20px;
                color: #78909c;
            }
            
            .empty-state-title {
                color: #00e676;
                font-size: 1.5em;
                margin-bottom: 10px;
                font-weight: 700;
            }
            
            @media (max-width: 768px) {
                .stats-grid { grid-template-columns: repeat(3, 1fr); }
                .history-sidebar { width: 100%; right: -100%; }
            }
        </style>
    </head>
    <body>
        <button class="history-toggle-btn" onclick="toggleHistory()">
             HISTORIQUE
            <span class="history-badge" id="historyCount">0</span>
        </button>
        
        <div class="history-sidebar" id="historySidebar">
            <div class="sidebar-header">
                <div class="sidebar-title">
                    <span></span>
                    <span>HISTORIQUE </span>
                </div>
                <button class="close-sidebar" onclick="toggleHistory()">✖ FERMER</button>
            </div>
            <div class="sidebar-content" id="historyContent">
                <div class="empty-state">
                    <div class="empty-state-title">✅ Aucun historique</div>
                </div>
            </div>
        </div>
        
        <div class="container">
            <div class="header">
                <div class="main-title">WIFI NETWORK SECURITY MONITOR v4.0</div>
                <div class="detection-list">
                    <span class="detection-badge">ARP Spoofing</span>
                    <span class="detection-badge">MAC Spoofing</span>
                    <span class="detection-badge">MITM Gateway</span>
                    <span class="detection-badge">DDoS Attack</span>
                    <span class="detection-badge">Nmap Scan</span>
                    <span class="detection-badge">Deauth Attack</span>
                    
                </div>
            </div>
            
            <div class="stats-grid" id="statsGrid"></div>
            
            <div class="chart-section">
                <div class="chart-title">📊 ACTIVITÉ RÉSEAU EN TEMPS RÉEL</div>
                <div class="chart-container">
                    <canvas id="activityChart"></canvas>
                </div>
            </div>
            
            <div class="section">
                <div class="section-header">
                    <h2>🚨 ALERTES ACTUELLES</h2>
                    <span class="section-count" id="currentAlertCount">0</span>
                </div>
                <div id="currentAlertsContainer">
                    <div class="empty-state">
                        <div class="empty-state-title">��� SYSTÈME SÉCURISÉ</div>
                        <p>Aucune menace active</p>
                    </div>
                </div>
            </div>
            
            <div class="section">
                <div class="section-header">
                    <h2>🚫 BLACKLIST IP</h2>
                    <span class="section-count" id="blacklistCount">0</span>
                </div>
                <div class="blacklist-form">
                    <input 
                        type="text" 
                        id="blacklistInput" 
                        class="blacklist-input" 
                        placeholder="192.168.1.100"
                    >
                    <button class="blacklist-btn" onclick="addToBlacklist()">
                        ➕ AJOUTER
                    </button>
                </div>
                <div id="blacklistContainer"></div>
            </div>
            
            <div class="section">
                <div class="section-header">
                    <h2>📱 APPAREILS CONNECTÉS</h2>
                    <span class="section-count" id="deviceCount">0</span>
                </div>
                <div id="devicesContainer"></div>
            </div>
        </div>
        
        <script>
            const ctx = document.getElementById('activityChart').getContext('2d');
            const activityChart = new Chart(ctx, {
                type: 'line',
                data: {
                    labels: [],
                    datasets: [{
                        label: 'Alertes',
                        data: [],
                        borderColor: '#ff1744',
                        backgroundColor: 'rgba(255, 23, 68, 0.1)',
                        borderWidth: 3,
                        tension: 0.4,
                        fill: true,
                        yAxisID: 'y'
                    }, {
                        label: 'Appareils',
                        data: [],
                        borderColor: '#00e676',
                        backgroundColor: 'rgba(0, 230, 118, 0.1)',
                        borderWidth: 3,
                        tension: 0.4,
                        fill: true,
                        yAxisID: 'y1'
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            labels: { color: '#fff', font: { size: 14, weight: 600 } }
                        }
                    },
                    scales: {
                        x: {
                            grid: { color: 'rgba(255, 255, 255, 0.05)' },
                            ticks: { color: '#b0bec5' }
                        },
                        y: {
                            position: 'left',
                            grid: { color: 'rgba(255, 255, 255, 0.05)' },
                            ticks: { color: '#ff5252' },
                            title: { display: true, text: 'Alertes', color: '#ff5252' }
                        },
                        y1: {
                            position: 'right',
                            grid: { drawOnChartArea: false },
                            ticks: { color: '#00e676' },
                            title: { display: true, text: 'Appareils', color: '#00e676' }
                        }
                    }
                }
            });
            
            async function updateStats() {
                try {
                    const response = await fetch('/api/current_stats');
                    const stats = await response.json();
                    
                    const statsGrid = document.getElementById('statsGrid');
                    statsGrid.classList.add('updating');
                    setTimeout(() => statsGrid.classList.remove('updating'), 800);
                    
                    statsGrid.innerHTML = `
                        <div class="stat-card">
                            <div class="live-indicator"></div>
                            <div class="stat-label">Appareils</div>
                            <div class="stat-number safe">${stats.total_devices}</div>
                            <div class="stat-sublabel">Connectés</div>
                        </div>
                        <div class="stat-card">
                            <div class="live-indicator"></div>
                            <div class="stat-label">Alertes</div>
                            <div class="stat-number ${stats.alert_count > 0 ? 'critical' : 'safe'}">${stats.alert_count}</div>
                            <div class="stat-sublabel">Actives</div>
                        </div>
                        <div class="stat-card">
                            <div class="live-indicator"></div>
                            <div class="stat-label">Trafic WiFi</div>
                            <div class="stat-number ${stats.network_packets > 200000 ? 'critical' : stats.network_packets > 100000 ? 'high' : 'safe'}">${stats.network_packets.toLocaleString()}</div>
                            <div class="stat-sublabel">${stats.packets_per_sec} pkt/s</div>
                        </div>
                        <div class="stat-card">
                            <div class="live-indicator"></div>
                            <div class="stat-label">DDoS</div>
                            <div class="stat-number ${stats.ddos_count > 0 ? 'critical' : 'neutral'}">${stats.ddos_count}</div>
                            <div class="stat-sublabel">Détectées</div>
                        </div>
                        <div class="stat-card">
                            <div class="live-indicator"></div>
                            <div class="stat-label">Dernier Scan</div>
                            <div class="stat-number" style="font-size:1.2em; color:#ff5252;">${stats.last_scan.split(' ')[1] || '--:--:--'}</div>
                            <div class="stat-sublabel">Horodatage</div>
                        </div>
                        <div class="stat-card">
                            <div class="live-indicator"></div>
                            <div class="stat-label">Status</div>
                            <div style="margin-top: 10px;">
                                <span class="status-badge status-${stats.status === 'SECURE' ? 'safe' : 'danger'}">${stats.status}</span>
                            </div>
                        </div>
                    `;
                } catch (error) {
                    console.error('❌ Erreur MAJ stats:', error);
                }
            }
            
            async function updateChart() {
                try {
                    const response = await fetch('/api/activity');
                    const data = await response.json();
                    if (data.alerts && data.alerts.length > 0) {
                        activityChart.data.labels = data.alerts.map(item => item.timestamp.split(' ')[1]);
                        activityChart.data.datasets[0].data = data.alerts.map(item => item.count);
                        activityChart.data.datasets[1].data = data.devices.map(item => item.count);
                        activityChart.update('none');
                    }
                } catch (error) {
                    console.error('❌ Erreur MAJ graphique:', error);
                }
            }
            
            async function updateCurrentAlerts() {
                try {
                    const response = await fetch('/api/current_alerts');
                    const data = await response.json();
                    const alerts = data.alerts || [];
                    
                    const countElement = document.getElementById('currentAlertCount');
                    if (countElement.textContent !== String(alerts.length)) {
                        countElement.style.transform = 'scale(1.2)';
                        setTimeout(() => countElement.style.transform = 'scale(1)', 300);
                    }
                    countElement.textContent = alerts.length;
                    
                    if (alerts.length === 0) {
                        document.getElementById('currentAlertsContainer').innerHTML = `
                            <div class="empty-state">
                                <div class="empty-state-title">✅ SYSTÈME SÉCURISÉ</div>
                                <p>Aucune menace active</p>
                            </div>
                        `;
                    } else {
                        document.getElementById('currentAlertsContainer').innerHTML = alerts.map(alert => `
                            <div class="alert alert-${alert.severity.toLowerCase()}">
                                <div class="alert-header">
                                    <div class="alert-title">${alert.description}</div>
                                    <span class="badge badge-${alert.severity.toLowerCase()}">${alert.severity}</span>
                                </div>
                                ${alert.ip ? `<div class="alert-details"><strong>🎯 IP:</strong> ${alert.ip}</div>` : ''}
                                ${alert.attacker_mac ? `<div class="alert-details"><strong>🔖 MAC:</strong> ${alert.attacker_mac}</div>` : ''}
                                ${alert.details ? `<div class="alert-details">${alert.details}</div>` : ''}
                                <div class="alert-details"><strong>💡</strong> ${alert.recommendation}</div>
                                ${alert.tool ? `<div class="alert-tool">🛠️ ${alert.tool}</div>` : ''}
                            </div>
                        `).join('');
                    }
                } catch (error) {
                    console.error('❌ Erreur MAJ alertes:', error);
                }
            }
            
            async function loadHistory() {
                try {
                    const response = await fetch('/api/alert_history');
                    const data = await response.json();
                    const alerts = data.alerts || [];
                    
                    document.getElementById('historyCount').textContent = alerts.length;
                    
                    if (alerts.length === 0) {
                        document.getElementById('historyContent').innerHTML = `
                            <div class="empty-state">
                                <div class="empty-state-title">✅ Aucun historique</div>
                            </div>
                        `;
                    } else {
                        document.getElementById('historyContent').innerHTML = alerts.reverse().map(alert => `
                            <div class="history-alert ${alert.severity.toLowerCase()}">
                                <div style="font-weight:700; margin-bottom:8px;">${alert.description}</div>
                                ${alert.ip ? `<div style="color:#ff5252; font-size:0.9em;">🎯 ${alert.ip}</div>` : ''}
                                ${alert.attacker_mac ? `<div style="color:#ffa726; font-size:0.85em;">🔖 ${alert.attacker_mac}</div>` : ''}
                                ${alert.details ? `<div style="color:#b0bec5; font-size:0.85em; margin:5px 0;">${alert.details}</div>` : ''}
                                ${alert.tool ? `<div style="color:#ffa726; font-size:0.75em; margin-top:5px;">🛠️ ${alert.tool}</div>` : ''}
                                <div style="color:#78909c; font-size:0.75em; margin-top:8px;">🕐 ${alert.timestamp}</div>
                            </div>
                        `).join('');
                    }
                } catch (error) {
                    console.error('❌ Erreur historique:', error);
                }
            }
            
            async function loadBlacklist() {
                try {
                    const response = await fetch('/api/blacklist');
                    const data = await response.json();
                    const blacklist = data.blacklist || [];
                    
                    document.getElementById('blacklistCount').textContent = blacklist.length;
                    
                    if (blacklist.length === 0) {
                        document.getElementById('blacklistContainer').innerHTML = '<div class="empty-state"><p>Aucune IP blacklistée</p></div>';
                        return;
                    }
                    
                    document.getElementById('blacklistContainer').innerHTML = blacklist.map(ip => `
                        <div class="blacklist-item">
                            <div class="blacklist-ip">🚫 ${ip}</div>
                            <button class="remove-btn" onclick="removeFromBlacklist('${ip}')">
                                ✖ RETIRER
                            </button>
                        </div>
                    `).join('');
                } catch (error) {
                    console.error('❌ Erreur blacklist:', error);
                }
            }
            
            async function addToBlacklist() {
                const input = document.getElementById('blacklistInput');
                const ip = input.value.trim();
                
                if (!ip) {
                    alert('❌ Veuillez entrer une IP');
                    return;
                }
                
                const ipRegex = /^(?:[0-9]{1,3}\\.){3}[0-9]{1,3}$/;
                if (!ipRegex.test(ip)) {
                    alert('❌ Format IP invalide');
                    return;
                }
                
                try {
                    const response = await fetch('/api/blacklist/add', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ ip: ip })
                    });
                    
                    const data = await response.json();
                    
                    if (response.ok) {
                        input.value = '';
                        loadBlacklist();
                        alert('✅ IP ajoutée');
                    } else {
                        alert('❌ ' + data.message);
                    }
                } catch (error) {
                    alert('❌ Erreur: ' + error);
                }
            }
            
            async function removeFromBlacklist(ip) {
                if (!confirm(`Retirer ${ip} ?`)) return;
                
                try {
                    const response = await fetch('/api/blacklist/remove', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ ip: ip })
                    });
                    
                    if (response.ok) {
                        loadBlacklist();
                        alert('✅ IP retirée');
                    }
                } catch (error) {
                    alert('❌ Erreur: ' + error);
                }
            }
            
            async function loadDevices() {
                try {
                    const response = await fetch('/api/devices');
                    const data = await response.json();
                    const devices = data.devices || {};
                    
                    const deviceCount = Object.keys(devices).length;
                    document.getElementById('deviceCount').textContent = deviceCount;
                    
                    if (deviceCount === 0) {
                        document.getElementById('devicesContainer').innerHTML = '<div class="empty-state"><p>Aucun appareil</p></div>';
                        return;
                    }
                    
                    document.getElementById('devicesContainer').innerHTML = Object.entries(devices).map(([mac, info]) => `
                        <div class="device-item">
                            <div class="device-main">
                                <div class="device-mac">${mac}</div>
                                <div class="device-details">
                                    <div class="device-detail"><strong>IP:</strong> ${info.ips.join(', ')}</div>
                                    <div class="device-detail"><strong>Type:</strong> ${info.type}</div>
                                    <div class="device-detail"><strong>Ports:</strong> ${info.open_ports.length}</div>
                                    <div class="device-detail"><strong>Vu:</strong> ${info.first_seen}</div>
                                </div>
                            </div>
                        </div>
                    `).join('');
                } catch (error) {
                    console.error('❌ Erreur devices:', error);
                }
            }
            
            function toggleHistory() {
                document.getElementById('historySidebar').classList.toggle('open');
                loadHistory();
            }
            
            document.getElementById('blacklistInput').addEventListener('keypress', function(e) {
                if (e.key === 'Enter') {
                    addToBlacklist();
                }
            });
            
            console.log('🚀 Monitoring avec détection pentest WiFi (5 min expiration)');
            
            updateStats();
            updateChart();
            updateCurrentAlerts();
            loadHistory();
            loadBlacklist();
            loadDevices();
            
            setInterval(() => {
                updateStats();
                console.log('🔄 Mise à jour stats');
            }, 5000);
            
            setInterval(() => {
                updateChart();
                console.log('📊 Mise à jour graphique');
            }, 5000);
            
            setInterval(() => {
                updateCurrentAlerts();
                console.log('🚨 Mise à jour alertes');
            }, 5000);
            
            setInterval(() => {
                loadDevices();
                console.log('📱 Mise à jour appareils');
            }, 10000);
            
            setInterval(loadHistory, 30000);
            
            console.log('✅ Monitoring actif! Détection WiFi pentest activée');
        </script>
    </body>
    </html>
    """
    
    return html

if __name__ == '__main__':
    print("╔════════════════════════════════════════╗")
    print("║  🛡️  WiFi Security Monitor v4.0       ║")
    print("║  http://192.168.1.249:5000            ║")
    print("╚════════════════════════════════════════╝\n")
    print("✅ Serveur démarré!")
    print("📡 Fonctionnalités:")
    print("   - Stats temps réel (5s) ⚡")
    print("   - Expiration alertes (5 min) ⏱️")
    print("   - Historique complet 📜")
    print("   - Blacklist IP 🚫")
    print("   - Appareils connectés 📱")
    print("\n🔍 En attente ESP8266...\n")
    
    app.run(host='0.0.0.0', port=5000, debug=True)