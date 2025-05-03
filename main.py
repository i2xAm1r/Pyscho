import customtkinter as ctk
from PIL import Image
import os
import socket
import getpass
import platform
import webbrowser
import shutil
import sys
import pathlib
import subprocess
import time
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import threading
import requests
import whois
from tkinter import filedialog
from PIL import Image
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ASSETS_PATH = os.path.join(BASE_DIR, "assets")


class NetworkToolkitApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Pyscho @i2xAm1r")
        self.geometry("800x800")
        self.resizable(False, False)

        self.theme_menu = ctk.CTkOptionMenu(
            self, values=["Dark", "Light"], command=self.change_theme, width=120)
        self.theme_menu.set("Dark")
        self.theme_menu.place(x=850, y=10)

        self.fullscreen = False
        self.fullscreen_button = ctk.CTkButton(
            self, text="Fullscreen", width=100, command=self.toggle_fullscreen)
        self.fullscreen_button.place(x=20, y=10)

        self.tabview = ctk.CTkTabview(self)
        self.tabview.pack(expand=True, fill="both", padx=10, pady=(60, 10))

        self.pentest_tab = self.tabview.add("Port Scanner")
        self.wifi_tab = self.tabview.add("WiFi Scanner")
        self.mac_tab = self.tabview.add("MAC Address Lookup")
        self.geolocation_tab = self.tabview.add("IP Geolocation")
        self.whois_tab = self.tabview.add("WHOIS Lookup")
        self.settings_tab = self.tabview.add("Info")
        self.about_tab = self.tabview.add("About")

        self.stop_flag = threading.Event()
        self.create_tool_template(
            self.pentest_tab, "Port Scanner", "pentest.png")
        self.create_tool_template(
            self.mac_tab, "MAC Address Lookup", "mac.png")
        self.create_tool_template(
            self.geolocation_tab, "IP Geolocation", "location.png")

        self.build_settings_tab()
        self.build_about_tab()
        self.build_footer()
        self.build_log_area()
        self.build_wifi_tab()
        self.build_port_scanner()
        self.build_mac_lookup()
        self.build_geolocation_tab()
        self.build_whois_tab()

    def build_geolocation_tab(self):
        ctk.CTkLabel(self.geolocation_tab,
                     text="Enter IP Address:").pack(pady=5)
        self.ip_entry_geolocation = ctk.CTkEntry(self.geolocation_tab)
        self.ip_entry_geolocation.pack()

        ctk.CTkButton(self.geolocation_tab, text="Get Geolocation",
                      command=self.get_ip_geolocation).pack(pady=5)

        self.geolocation_result = ctk.CTkTextbox(
            self.geolocation_tab, height=200, font=ctk.CTkFont(size=13))
        self.geolocation_result.pack(fill="both", padx=10, pady=10)

    def get_ip_geolocation(self):
        ip = self.ip_entry_geolocation.get().strip()
        if not ip:
            self.log("❌ Please enter an IP address.")
            return
        try:
            response = requests.get(f"https://ipinfo.io/{ip}/json")
            data = response.json()

            country = data.get("country", "N/A")
            city = data.get("city", "N/A")
            region = data.get("region", "N/A")
            location = data.get("loc", "N/A")
            isp = data.get("org", "N/A")

            result = f"IP: {ip}\nCountry: {country}\nCity: {city}\nRegion: {region}\nLocation: {location}\nISP: {isp}"
            self.geolocation_result.delete("1.0", "end")
            self.geolocation_result.insert("end", result)

            self.log(f"🌍 Geolocation data fetched for IP: {ip}")

        except Exception as e:
            self.log(f"❌ Error fetching geolocation: {e}")

    def build_whois_tab(self):
        whois_icon_path = os.path.join(ASSETS_PATH, "skull.png")
        whois_image = ctk.CTkImage(
        light_image=Image.open(whois_icon_path), size=(90, 90))
        ctk.CTkLabel(self.whois_tab, image=whois_image, text="").pack(pady=(20, 5))
        
        ctk.CTkLabel(self.whois_tab, text="WHOIS Lookup", font=ctk.CTkFont(
            size=30, weight="bold")).pack(pady=(0, 10))
        ctk.CTkLabel(self.whois_tab, text="Enter Domain Name:").pack(pady=5)
        self.domain_entry_whois = ctk.CTkEntry(self.whois_tab)
        self.domain_entry_whois.pack()

        ctk.CTkButton(self.whois_tab, text="Get WHOIS Info",
                      command=self.get_whois_info).pack(pady=5)

        self.whois_result = ctk.CTkTextbox(
        self.whois_tab, height=200, font=ctk.CTkFont(size=13))
        self.whois_result.pack(fill="both", padx=10, pady=10)

    def get_whois_info(self):
        domain = self.domain_entry_whois.get().strip()
        if not domain:
           self.log("❌ Please enter a domain.")
           return

        try:
            response = requests.get(f"https://rdap.org/domain/{domain}")
            if response.status_code == 200:
                data = response.json()

                registrar = data.get("registrar", {}).get("name", "N/A")
                status = ", ".join(data.get("status", [])) or "N/A"
                nameservers = ", ".join(ns.get("ldhName", "")
                                    for ns in data.get("nameservers", [])) or "N/A"
                events = data.get("events", [])
                created = next(
                (e["eventDate"] for e in events if e["eventAction"] == "registration"), "N/A")
                expires = next(
                (e["eventDate"] for e in events if e["eventAction"] == "expiration"), "N/A")

                result = (
                    f"Domain: {domain}\n"
                    f"Registrar: {registrar}\n"
                    f"Status: {status}\n"
                    f"Created On: {created}\n"
                    f"Expires On: {expires}\n"
                    f"Name Servers: {nameservers}\n"
                )
                self.whois_result.delete("1.0", "end")
                self.whois_result.insert("end", result)
                self.log(f"📜 WHOIS info fetched for domain: {domain}")
            else:
                self.log(f"❌ RDAP error {response.status_code}: {response.text}")
        except Exception as e:
            self.log(f"❌ Error fetching WHOIS info: {e}")

    def load_ports_from_file(self):
        file_path = filedialog.askopenfilename(
            title="Select Port File", filetypes=[("Text Files", "*.txt")])
        if file_path:
            try:
                with open(file_path, "r") as f:
                    ports = [line.strip() for line in f if line.strip().isdigit()]
                    self.port_entry.delete(0, "end")
                    self.port_entry.insert(0, ",".join(ports))
                    self.log(f"📂 Loaded {len(ports)} ports from file.")
            except Exception as e:
                self.log(f"❌ Failed to load ports: {e}")

    def copy_wifi_log(self):
        self.clipboard_clear()
        self.clipboard_append(self.wifi_info_textbox.get("1.0", "end").strip())
        self.log("📋 WiFi info copied to clipboard.")

    def export_wifi_log(self):
        try:
            filepath = os.path.join(BASE_DIR, "wifi_log.txt")
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(self.wifi_info_textbox.get("1.0", "end").strip())
            self.log(f"💾 WiFi log saved to {filepath}")
        except Exception as e:
            self.log(f"❌ Error saving WiFi log: {e}")

    def toggle_fullscreen(self):
        self.fullscreen = not self.fullscreen
        self.attributes("-fullscreen", self.fullscreen)

    def create_tool_template(self, tab, title, image_file):
        try:
            image_path = os.path.join(ASSETS_PATH, image_file)
            img = ctk.CTkImage(light_image=Image.open(
                image_path), size=(100, 100))
        except:
            img = None

        image_label = ctk.CTkLabel(tab, text="", image=img)
        image_label.pack(pady=10)

        title_label = ctk.CTkLabel(
            tab, text=title, font=ctk.CTkFont(size=20, weight="bold"))
        title_label.pack(pady=5)

    def build_wifi_tab(self):
        ctk.CTkButton(self.wifi_tab, text="Scan WiFi",
                      command=self.scan_wifi).pack(pady=5)
        ctk.CTkButton(self.wifi_tab, text="Copy Log",
                      command=self.copy_wifi_log).pack(pady=5)
        ctk.CTkButton(self.wifi_tab, text="Extract to File",
                      command=self.export_wifi_log).pack(pady=5)
        self.wifi_fig, self.wifi_ax = plt.subplots(figsize=(10, 3))
        self.wifi_canvas = FigureCanvasTkAgg(
            self.wifi_fig, master=self.wifi_tab)
        self.wifi_canvas.get_tk_widget().pack()

        self.wifi_info_textbox = ctk.CTkTextbox(
            self.wifi_tab, height=100, font=ctk.CTkFont(size=13))
        self.wifi_info_textbox.pack(fill="both", padx=10, pady=10)

    def scan_wifi(self):
        def thread_scan():
            self.log("Scanning WiFi networks...")
            try:
                output = subprocess.check_output(
                    "netsh wlan show networks mode=bssid", shell=True, text=True)
                networks = self.parse_wifi_output(output)
                self.display_wifi_chart(networks)
            except Exception as e:
                self.log(f"Error scanning WiFi: {e}")

        threading.Thread(target=thread_scan).start()

    def parse_wifi_output(self, output):
        networks = []
        ssid = None
        signal = None
        channel = None
        bssid = None
        for line in output.splitlines():
            line = line.strip()
            if line.startswith("SSID ") and " : " in line:
                ssid = line.split(" : ")[1].strip()
            elif line.startswith("Signal") and " : " in line:
                signal = line.split(" : ")[1].strip()
            elif line.startswith("Channel") and " : " in line:
                channel = line.split(" : ")[1].strip()
            elif line.startswith("BSSID") and " : " in line:
                bssid = line.split(" : ")[1].strip()
                if ssid and signal and channel and bssid:
                    networks.append({
                        "ssid": ssid,
                        "channel": channel,
                        "bssid": bssid,
                        "signal": int(signal.replace("%", "")),
                    })
        return networks

    def display_wifi_chart(self, networks):
        self.wifi_ax.clear()
        self.wifi_info_textbox.configure(state="normal")
        self.wifi_info_textbox.delete("1.0", "end")

        if networks:
            labels = [net["ssid"] for net in networks]
            signals = [net["signal"] for net in networks]
            self.wifi_ax.barh(labels, signals, color="#1f77b4")
            self.wifi_ax.set_xlabel("Signal Strength (%)")
            self.wifi_ax.set_title("WiFi Networks")
            self.wifi_ax.invert_yaxis()

            for net in networks:
                info_line = f"SSID: {net['ssid']}\nBSSID (MAC): {net['bssid']}\nChannel: {net['channel']}\nSignal: {net['signal']}%\n\n"
                self.wifi_info_textbox.insert("end", info_line)
        else:
            self.wifi_ax.text(0.5, 0.5, "No networks found", ha='center')
            self.wifi_info_textbox.insert("end", "No networks found.")

        self.wifi_info_textbox.configure(state="disabled")
        self.wifi_canvas.draw()

    def build_port_scanner(self):
        ctk.CTkLabel(self.pentest_tab,
                     text="Enter IP Address to Scan:").pack(pady=2)
        self.ip_entry = ctk.CTkEntry(self.pentest_tab)
        self.ip_entry.pack()

        ctk.CTkLabel(self.pentest_tab,
                     text="Enter Ports (e.g., 22,80,443) or leave blank for full scan:").pack(pady=2)
        self.port_entry = ctk.CTkEntry(self.pentest_tab)
        self.port_entry.pack()

        ctk.CTkButton(self.pentest_tab, text="Load Ports from File",
                      command=self.load_ports_from_file).pack(pady=5)

        ctk.CTkButton(self.pentest_tab, text="Full Scan (443, 80, Cloudflare)",
                      command=self.start_full_port_scan).pack(pady=5)

        ctk.CTkButton(self.pentest_tab, text="Custom Port Scan",
                      command=self.start_custom_port_scan).pack(pady=5)

        self.stop_scan_button = ctk.CTkButton(
            self.pentest_tab, text="Stop Scan", command=self.stop_scan, state="disabled")
        self.stop_scan_button.pack(pady=5)

        self.output_box = ctk.CTkTextbox(self.pentest_tab, height=200)
        self.output_box.pack(padx=10, pady=10, fill="both", expand=True)

    def start_full_port_scan(self):
        ip = self.ip_entry.get().strip()
        ports = [443, 80, 2053, 2083, 2087, 2096]
        self.log(f"🔍 Full scanning {ip} on ports: {ports}")
        threading.Thread(target=self.perform_port_scan,
                         args=(ip, ports)).start()

    def start_custom_port_scan(self):
        ip = self.ip_entry.get().strip()
        ports_str = self.port_entry.get().strip()
        ports = [int(p.strip())
                 for p in ports_str.split(',') if p.strip().isdigit()]
        self.log(f"🔍 Custom scanning {ip} on ports: {ports}")
        threading.Thread(target=self.perform_port_scan,
                         args=(ip, ports)).start()

    def perform_port_scan(self, ip, ports):
        self.stop_flag.clear()
        self.stop_scan_button.configure(state="normal")
        open_ports = []
        for port in ports:
            if self.stop_flag.is_set():
                self.log("⛔ Scan manually stopped.")
                break

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            if result == 0:
                open_ports.append(port)
                self.log(f"✅ Port {port} is open.")
            else:
                self.log(f"❌ Port {port} is closed.")
            sock.close()

        self.stop_scan_button.configure(state="disabled")
        self.log(f"✔️ Scan finished. Open ports on {ip}: {open_ports}")

    def stop_scan(self):
        self.stop_flag.set()
        self.stop_scan_button.configure(state="disabled")
        self.log("🔴 Scan stop requested.")

    def build_mac_lookup(self):
        mac_label = ctk.CTkLabel(
            self.mac_tab, text="Enter MAC Address to Lookup:")
        mac_label.pack(pady=2)

        self.mac_entry = ctk.CTkEntry(self.mac_tab)
        self.mac_entry.pack()

        lookup_btn = ctk.CTkButton(
            self.mac_tab, text="Lookup MAC Address", command=self.lookup_mac)
        lookup_btn.pack(pady=8)

        description_label = ctk.CTkLabel(
            self.mac_tab,
            text="This tool allows you to check the vendor/manufacturer of a device by its MAC address.\nUseful for identifying unknown devices on your network.",
            font=ctk.CTkFont(size=14),
            wraplength=800,
            justify="center"
        )
        description_label.pack(pady=10)

    def lookup_mac(self):
        mac = self.mac_entry.get()
        self.log(f"🔍 Looking up MAC address {mac}...")
        vendor = self.get_mac_vendor(mac)
        self.log(f"✅ Vendor: {vendor}")

    def get_mac_vendor(self, mac):
        api_url = f"https://api.macvendors.com/{mac}"
        try:
            response = requests.get(api_url)
            return response.text.strip()
        except requests.exceptions.RequestException:
            return "Unknown"

    def build_settings_tab(self):
        title = ctk.CTkLabel(self.settings_tab, text="Application Info",
                             font=ctk.CTkFont(size=24, weight="bold"))
        title.pack(pady=15)

        info_text = (
            "Name: Pyscho\n"
            "Version: 1.0.0\n"
            "License: MIT\n"
            "Developer: 2xAm1r\n\n"
            "- Network diagnostics\n"
            "- Penetration testing (educational)\n"
            "- Modular and expandable design\n\n"
            "Modules Included:\n"
            "✓ WHOIS Lookup\n"
            "✓ IP Geolocation\n"
            "✓ Port Scanner\n"
            "✓ WiFi Scanner\n"
            "✓ MAC Address Lookup\n"
            "This project is open-source and will receive regular updates."
        )
        info_label = ctk.CTkLabel(self.settings_tab, text=info_text,
                                  font=ctk.CTkFont(size=18), justify="center")
        info_label.pack(pady=10)
        
        settings_img_path = os.path.join(
            ASSETS_PATH, "angel.png")  # نام فایل دلخواه
        settings_img = ctk.CTkImage(light_image=Image.open(
        settings_img_path), size=(150, 150))
        ctk.CTkLabel(self.settings_tab, image=settings_img, text="").pack(pady=15)

    def build_about_tab(self):
        ctk.CTkLabel(self.about_tab, text="Network & Pentest Toolkit",
                 font=ctk.CTkFont(size=25, weight="bold")).pack(pady=10)
        ctk.CTkLabel(self.about_tab, text="Developed by 2xAm1r © 2025",
                     font=ctk.CTkFont(size=15, weight="bold")).pack(pady=10)
        ctk.CTkLabel(self.about_tab, text="Links:",
                 font=ctk.CTkFont(size=15)).pack(pady=10)

        frame = ctk.CTkFrame(self.about_tab)
        frame.pack(pady=5)

        github_icon = ctk.CTkImage(Image.open(
            os.path.join(ASSETS_PATH, "github.png")), size=(45, 45))
        telegram_icon = ctk.CTkImage(Image.open(
            os.path.join(ASSETS_PATH, "telegram.png")), size=(45, 45))
        web_icon = ctk.CTkImage(Image.open(
            os.path.join(ASSETS_PATH, "instagram.png")), size=(45, 45))

        github_btn = ctk.CTkButton(frame, image=github_icon, text="Github", width=40,
                               command=lambda: webbrowser.open("https://github.com/i2xam1r"))
        telegram_btn = ctk.CTkButton(frame, image=telegram_icon, text="Telegram",
                                 width=40, command=lambda: webbrowser.open("https://t.me/i2xam1r"))
        web_btn = ctk.CTkButton(frame, image=web_icon, text="Instagram", width=40,
                            command=lambda: webbrowser.open("https://instagram.com/2xAm1r"))

        banner_path = os.path.join(ASSETS_PATH, "shakespeare.png")
        if os.path.exists(banner_path):
            banner_image = ctk.CTkImage(Image.open(banner_path), size=(300, 300))
            ctk.CTkLabel(self.about_tab, image=banner_image, text="").pack(pady=20)

        github_btn.pack(side="left", padx=10)
        telegram_btn.pack(side="left", padx=10)
        web_btn.pack(side="left", padx=10)


    def open_github(self):
        webbrowser.open("https://github.com/i2xAm1r")
        self.log("🌐 Opened GitHub repository.")

    def open_donation(self):
        webbrowser.open("http://coffeete.ir/am1r")
        self.log("☕ Opened donation link.")

    def download_app(self):
        webbrowser.open("https://github.com/i2xAm1r/Pyscho/releases")
        self.log("⬇️ Opened download page.")

    def get_ip(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0)
        try:
            s.connect(('10.254.254.254', 1))
            ip = s.getsockname()[0]
        except:
            ip = '127.0.0.1'
        finally:
            s.close()
        return ip

    def build_footer(self):
        footer_frame = ctk.CTkFrame(self, height=50)
        footer_frame.pack(side="bottom", fill="x", pady=10)

        ctk.CTkLabel(footer_frame, text="Developer: 2xAm1r",
                     font=ctk.CTkFont(size=12)).pack(side="left", padx=10)
        ctk.CTkButton(footer_frame, text="Download",
                      command=self.download_app, width=100).pack(side="left", padx=10)
        self.startup_var = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(footer_frame, text="Run at Startup", variable=self.startup_var,
                        command=self.set_startup).pack(side="left", padx=10)
        ctk.CTkLabel(footer_frame, text="Version 1.0.0",
                     font=ctk.CTkFont(size=12)).pack(side="right", padx=10)

    def build_log_area(self):
        log_frame = ctk.CTkFrame(self, height=100)
        log_frame.pack(side="bottom", fill="x", padx=10)

        self.log_box = ctk.CTkTextbox(
            log_frame, height=160, state="disabled", font=ctk.CTkFont(size=14))
        self.log_box.pack(fill="both", padx=10, pady=5)

        self.clear_log_button = ctk.CTkButton(
            log_frame, text="Clear Log", command=self.clear_log, width=100)
        self.clear_log_button.pack(side="right", padx=10)

        self.log("✅ Application started.")

    def clear_log(self):
        self.log_box.configure(state="normal")
        self.log_box.delete("1.0", "end")
        self.log_box.configure(state="disabled")


    def log(self, message):
        self.log_box.configure(state="normal")
        self.log_box.insert("end", f"{message}\n")
        self.log_box.configure(state="disabled")
        self.log_box.see("end")
        if hasattr(self, "port_scan_log"):
            self.port_scan_log += f"{message}\n"

    def change_theme(self, new_theme):
        ctk.set_appearance_mode(new_theme.lower())

    def set_startup(self):
        if self.startup_var.get():
            self.add_to_startup()
            self.log("✅ Enabled run at startup.")
        else:
            self.remove_from_startup()
            self.log("❌ Disabled run at startup.")

    def add_to_startup(self):
        if sys.platform == "win32":
            startup_folder = pathlib.Path(
                rf"C:\\Users\\{getpass.getuser()}\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup")
            shutil.copy2(sys.argv[0], startup_folder / "Pyscho.exe")

    def remove_from_startup(self):
        if sys.platform == "win32":
            startup_folder = pathlib.Path(
                rf"C:\\Users\\{getpass.getuser()}\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup")
            target_path = startup_folder / "Pyscho.exe"
            if target_path.exists():
                os.remove(target_path)


if __name__ == "__main__":
    app = NetworkToolkitApp()
    app.mainloop()
