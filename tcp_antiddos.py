import socket
import threading
import time
import os
import sys
import ipaddress
import datetime
import logging
from collections import defaultdict, deque
import queue
import signal
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import numpy as np
import json
import uuid

class TCPAntiDDOS:
    def __init__(self):
        self.connections = defaultdict(int)
        self.blocked_ips = set()
        self.connection_history = defaultdict(lambda: deque(maxlen=1000))
        self.threshold = 50
        self.block_time = 300
        self.whitelist = set()
        self.log_queue = queue.Queue()
        self.packet_stats = {
            'total': 0,
            'blocked': 0,
            'allowed': 0
        }
        self.running = False
        self.lock = threading.Lock()
        self.load_config()
        self.setup_logging()
        
    def load_config(self):
        try:
            if os.path.exists('config.json'):
                with open('config.json', 'r') as f:
                    config = json.load(f)
                    self.threshold = config.get('threshold', 50)
                    self.block_time = config.get('block_time', 300)
                    self.whitelist = set(config.get('whitelist', []))
        except Exception as e:
            logging.error(f"Failed to load config: {e}")
    
    def save_config(self):
        try:
            config = {
                'threshold': self.threshold,
                'block_time': self.block_time,
                'whitelist': list(self.whitelist)
            }
            with open('config.json', 'w') as f:
                json.dump(config, f, indent=4)
        except Exception as e:
            logging.error(f"Failed to save config: {e}")
    
    def setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler("antiddos.log"),
                logging.StreamHandler()
            ]
        )
    
    def is_blocked(self, ip):
        return ip in self.blocked_ips

    def is_whitelisted(self, ip):
        return ip in self.whitelist
    
    def add_to_whitelist(self, ip):
        try:
            ipaddress.ip_address(ip)
            with self.lock:
                self.whitelist.add(ip)
                if ip in self.blocked_ips:
                    self.blocked_ips.remove(ip)
            self.save_config()
            self.log_message(f"Added {ip} to whitelist")
            return True
        except ValueError:
            self.log_message(f"Invalid IP address: {ip}")
            return False
    
    def remove_from_whitelist(self, ip):
        with self.lock:
            if ip in self.whitelist:
                self.whitelist.remove(ip)
                self.save_config()
                self.log_message(f"Removed {ip} from whitelist")
                return True
        return False
    
    def block_ip(self, ip, reason="Exceed connection threshold"):
        if not self.is_whitelisted(ip):
            with self.lock:
                self.blocked_ips.add(ip)
                self.packet_stats['blocked'] += 1
            self.log_message(f"Blocked IP {ip}: {reason}")
            threading.Timer(self.block_time, self.unblock_ip, args=[ip]).start()
    
    def unblock_ip(self, ip):
        with self.lock:
            if ip in self.blocked_ips:
                self.blocked_ips.remove(ip)
                self.log_message(f"Unblocked IP {ip}")
    
    def analyze_packet(self, packet_info):
        ip = packet_info['src_ip']
        
        if self.is_blocked(ip):
            return False
        
        if self.is_whitelisted(ip):
            self.packet_stats['allowed'] += 1
            return True
        
        current_time = time.time()
        with self.lock:
            self.connections[ip] += 1
            self.connection_history[ip].append(current_time)
            self.packet_stats['total'] += 1
            
            if len(self.connection_history[ip]) >= self.threshold:
                first_conn = self.connection_history[ip][0]
                if current_time - first_conn < 60:
                    self.block_ip(ip)
                    return False
        
        self.packet_stats['allowed'] += 1
        return True
    
    def start_monitor(self, interface="0.0.0.0", port=8080):
        if self.running:
            return
        
        try:
            self.running = True
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((interface, port))
            self.server_socket.listen(5)
            
            self.log_message(f"TCP Anti-DDOS monitor started on {interface}:{port}")
            
            def accept_connections():
                while self.running:
                    try:
                        client_socket, addr = self.server_socket.accept()
                        threading.Thread(target=self.handle_client, args=(client_socket, addr)).start()
                    except Exception as e:
                        if self.running:
                            self.log_message(f"Error accepting connection: {e}")
            
            self.accept_thread = threading.Thread(target=accept_connections)
            self.accept_thread.daemon = True
            self.accept_thread.start()
            
        except Exception as e:
            self.running = False
            self.log_message(f"Failed to start monitor: {e}")
    
    def handle_client(self, client_socket, addr):
        ip = addr[0]
        packet_info = {
            'src_ip': ip,
            'src_port': addr[1],
            'timestamp': time.time()
        }
        
        allowed = self.analyze_packet(packet_info)
        
        if allowed:
            try:
                client_socket.send(b"Connection accepted\n")
            except:
                pass
        else:
            try:
                client_socket.send(b"Connection blocked\n")
            except:
                pass
        
        client_socket.close()
    
    def stop_monitor(self):
        if not self.running:
            return
        
        self.running = False
        try:
            self.server_socket.close()
        except:
            pass
        
        self.log_message("TCP Anti-DDOS monitor stopped")
    
    def log_message(self, message):
        logging.info(message)
        self.log_queue.put(message)

class AntiDDOSGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("TCP Anti-DDOS by huesss")
        self.root.geometry("1000x700")
        self.root.minsize(800, 600)
        
        self.antiddos = TCPAntiDDOS()
        
        self.setup_styles()
        self.create_widgets()
        self.poll_logs()
        self.update_stats()
    
    def setup_styles(self):
        style = ttk.Style()
        style.configure('TButton', font=('Segoe UI', 10))
        style.configure('TLabel', font=('Segoe UI', 10))
        style.configure('Header.TLabel', font=('Segoe UI', 12, 'bold'))
        style.configure('Stats.TLabel', font=('Segoe UI', 11))
        
        self.root.option_add('*TCombobox*Listbox.font', ('Segoe UI', 10))
    
    def create_widgets(self):
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        left_frame = ttk.Frame(main_frame)
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))
        
        right_frame = ttk.Frame(main_frame)
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(5, 0))
        
        self.create_control_panel(left_frame)
        self.create_log_panel(left_frame)
        self.create_whitelist_panel(right_frame)
        self.create_stats_panel(right_frame)
    
    def create_control_panel(self, parent):
        control_frame = ttk.LabelFrame(parent, text="Управление", padding="10")
        control_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(control_frame, text="IP:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.ip_var = tk.StringVar(value="0.0.0.0")
        ip_entry = ttk.Entry(control_frame, textvariable=self.ip_var, width=15)
        ip_entry.grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)
        
        ttk.Label(control_frame, text="Порт:").grid(row=0, column=2, padx=5, pady=5, sticky=tk.W)
        self.port_var = tk.IntVar(value=8080)
        port_entry = ttk.Entry(control_frame, textvariable=self.port_var, width=6)
        port_entry.grid(row=0, column=3, padx=5, pady=5, sticky=tk.W)
        
        ttk.Label(control_frame, text="Порог:").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.threshold_var = tk.IntVar(value=self.antiddos.threshold)
        threshold_entry = ttk.Entry(control_frame, textvariable=self.threshold_var, width=6)
        threshold_entry.grid(row=1, column=1, padx=5, pady=5, sticky=tk.W)
        
        ttk.Label(control_frame, text="Время блокировки (сек):").grid(row=1, column=2, padx=5, pady=5, sticky=tk.W)
        self.block_time_var = tk.IntVar(value=self.antiddos.block_time)
        block_time_entry = ttk.Entry(control_frame, textvariable=self.block_time_var, width=6)
        block_time_entry.grid(row=1, column=3, padx=5, pady=5, sticky=tk.W)
        
        self.start_button = ttk.Button(control_frame, text="Запустить", command=self.start_monitoring)
        self.start_button.grid(row=2, column=0, columnspan=2, padx=5, pady=10, sticky=tk.W)
        
        self.stop_button = ttk.Button(control_frame, text="Остановить", command=self.stop_monitoring, state=tk.DISABLED)
        self.stop_button.grid(row=2, column=2, columnspan=2, padx=5, pady=10, sticky=tk.W)
        
        apply_button = ttk.Button(control_frame, text="Применить настройки", command=self.apply_settings)
        apply_button.grid(row=3, column=0, columnspan=4, padx=5, pady=5, sticky=tk.EW)
    
    def create_log_panel(self, parent):
        log_frame = ttk.LabelFrame(parent, text="Журнал событий", padding="10")
        log_frame.pack(fill=tk.BOTH, expand=True)
        
        self.log_text = scrolledtext.ScrolledText(log_frame, height=15)
        self.log_text.pack(fill=tk.BOTH, expand=True)
        self.log_text.config(state=tk.DISABLED)
        
        clear_button = ttk.Button(log_frame, text="Очистить журнал", command=self.clear_logs)
        clear_button.pack(pady=(5, 0))
    
    def create_whitelist_panel(self, parent):
        whitelist_frame = ttk.LabelFrame(parent, text="Белый список", padding="10")
        whitelist_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        input_frame = ttk.Frame(whitelist_frame)
        input_frame.pack(fill=tk.X, pady=(0, 5))
        
        ttk.Label(input_frame, text="IP:").pack(side=tk.LEFT, padx=5)
        self.whitelist_ip_var = tk.StringVar()
        whitelist_entry = ttk.Entry(input_frame, textvariable=self.whitelist_ip_var, width=20)
        whitelist_entry.pack(side=tk.LEFT, padx=5)
        
        add_button = ttk.Button(input_frame, text="Добавить", command=self.add_to_whitelist)
        add_button.pack(side=tk.LEFT, padx=5)
        
        remove_button = ttk.Button(input_frame, text="Удалить", command=self.remove_from_whitelist)
        remove_button.pack(side=tk.LEFT, padx=5)
        
        whitelist_list_frame = ttk.Frame(whitelist_frame)
        whitelist_list_frame.pack(fill=tk.BOTH, expand=True)
        
        self.whitelist_listbox = tk.Listbox(whitelist_list_frame, height=10)
        self.whitelist_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        whitelist_scrollbar = ttk.Scrollbar(whitelist_list_frame, orient=tk.VERTICAL, command=self.whitelist_listbox.yview)
        whitelist_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.whitelist_listbox.config(yscrollcommand=whitelist_scrollbar.set)
        
        self.update_whitelist_display()
    
    def create_stats_panel(self, parent):
        stats_frame = ttk.LabelFrame(parent, text="Статистика", padding="10")
        stats_frame.pack(fill=tk.BOTH, expand=True)
        
        counters_frame = ttk.Frame(stats_frame)
        counters_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(counters_frame, text="Всего пакетов:", style="Stats.TLabel").grid(row=0, column=0, sticky=tk.W, padx=5, pady=2)
        self.total_packets_label = ttk.Label(counters_frame, text="0", style="Stats.TLabel")
        self.total_packets_label.grid(row=0, column=1, sticky=tk.W, padx=5, pady=2)
        
        ttk.Label(counters_frame, text="Заблокировано:", style="Stats.TLabel").grid(row=1, column=0, sticky=tk.W, padx=5, pady=2)
        self.blocked_packets_label = ttk.Label(counters_frame, text="0", style="Stats.TLabel")
        self.blocked_packets_label.grid(row=1, column=1, sticky=tk.W, padx=5, pady=2)
        
        ttk.Label(counters_frame, text="Пропущено:", style="Stats.TLabel").grid(row=2, column=0, sticky=tk.W, padx=5, pady=2)
        self.allowed_packets_label = ttk.Label(counters_frame, text="0", style="Stats.TLabel")
        self.allowed_packets_label.grid(row=2, column=1, sticky=tk.W, padx=5, pady=2)
        
        ttk.Label(counters_frame, text="Заблокировано IP:", style="Stats.TLabel").grid(row=3, column=0, sticky=tk.W, padx=5, pady=2)
        self.blocked_ips_label = ttk.Label(counters_frame, text="0", style="Stats.TLabel")
        self.blocked_ips_label.grid(row=3, column=1, sticky=tk.W, padx=5, pady=2)
        
        ttk.Separator(stats_frame, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=5)
        
        self.figure = plt.Figure(figsize=(5, 4), dpi=100)
        self.ax = self.figure.add_subplot(111)
        self.canvas = FigureCanvasTkAgg(self.figure, stats_frame)
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        self.traffic_data = {
            'timestamps': [],
            'allowed': [],
            'blocked': []
        }
        self.update_graph()
    
    def poll_logs(self):
        try:
            while not self.antiddos.log_queue.empty():
                message = self.antiddos.log_queue.get_nowait()
                self.log_text.config(state=tk.NORMAL)
                self.log_text.insert(tk.END, f"{message}\n")
                self.log_text.see(tk.END)
                self.log_text.config(state=tk.DISABLED)
        except:
            pass
        finally:
            self.root.after(100, self.poll_logs)
    
    def update_stats(self):
        self.total_packets_label.config(text=str(self.antiddos.packet_stats['total']))
        self.blocked_packets_label.config(text=str(self.antiddos.packet_stats['blocked']))
        self.allowed_packets_label.config(text=str(self.antiddos.packet_stats['allowed']))
        self.blocked_ips_label.config(text=str(len(self.antiddos.blocked_ips)))
        
        current_time = time.time()
        self.traffic_data['timestamps'].append(current_time)
        self.traffic_data['allowed'].append(self.antiddos.packet_stats['allowed'])
        self.traffic_data['blocked'].append(self.antiddos.packet_stats['blocked'])
        
        if len(self.traffic_data['timestamps']) > 60:
            self.traffic_data['timestamps'] = self.traffic_data['timestamps'][-60:]
            self.traffic_data['allowed'] = self.traffic_data['allowed'][-60:]
            self.traffic_data['blocked'] = self.traffic_data['blocked'][-60:]
        
        self.update_graph()
        self.root.after(1000, self.update_stats)
    
    def update_graph(self):
        self.ax.clear()
        
        if len(self.traffic_data['timestamps']) > 1:
            timestamps = [datetime.datetime.fromtimestamp(ts) for ts in self.traffic_data['timestamps']]
            
            self.ax.plot(timestamps, self.traffic_data['allowed'], 'g-', label='Пропущено')
            self.ax.plot(timestamps, self.traffic_data['blocked'], 'r-', label='Заблокировано')
            
            self.ax.set_title('Статистика трафика')
            self.ax.set_xlabel('Время')
            self.ax.set_ylabel('Количество пакетов')
            self.ax.legend()
            
            self.ax.tick_params(axis='x', rotation=45)
            self.ax.xaxis.set_major_formatter(plt.matplotlib.dates.DateFormatter('%H:%M:%S'))
            
            self.figure.tight_layout()
            self.canvas.draw()
    
    def start_monitoring(self):
        try:
            ip = self.ip_var.get()
            port = self.port_var.get()
            
            self.antiddos.start_monitor(ip, port)
            
            self.start_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.NORMAL)
            
            self.log_message(f"Мониторинг запущен на {ip}:{port}")
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось запустить мониторинг: {e}")
    
    def stop_monitoring(self):
        self.antiddos.stop_monitor()
        
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        
        self.log_message("Мониторинг остановлен")
    
    def apply_settings(self):
        try:
            threshold = self.threshold_var.get()
            block_time = self.block_time_var.get()
            
            if threshold < 1:
                raise ValueError("Порог должен быть больше 0")
            
            if block_time < 1:
                raise ValueError("Время блокировки должно быть больше 0")
            
            self.antiddos.threshold = threshold
            self.antiddos.block_time = block_time
            self.antiddos.save_config()
            
            self.log_message(f"Настройки применены: порог={threshold}, время блокировки={block_time} секунд")
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось применить настройки: {e}")
    
    def add_to_whitelist(self):
        ip = self.whitelist_ip_var.get().strip()
        if ip:
            if self.antiddos.add_to_whitelist(ip):
                self.whitelist_ip_var.set("")
                self.update_whitelist_display()
            else:
                messagebox.showerror("Ошибка", f"Неверный формат IP-адреса: {ip}")
    
    def remove_from_whitelist(self):
        selection = self.whitelist_listbox.curselection()
        if selection:
            ip = self.whitelist_listbox.get(selection[0])
            if self.antiddos.remove_from_whitelist(ip):
                self.update_whitelist_display()
    
    def update_whitelist_display(self):
        self.whitelist_listbox.delete(0, tk.END)
        for ip in sorted(self.antiddos.whitelist):
            self.whitelist_listbox.insert(tk.END, ip)
    
    def clear_logs(self):
        self.log_text.config(state=tk.NORMAL)
        self.log_text.delete(1.0, tk.END)
        self.log_text.config(state=tk.DISABLED)
    
    def log_message(self, message):
        self.antiddos.log_message(message)

def main():
    root = tk.Tk()
    app = AntiDDOSGUI(root)
    
    def on_closing():
        if hasattr(app, 'antiddos') and app.antiddos.running:
            app.stop_monitoring()
        root.destroy()
    
    root.protocol("WM_DELETE_WINDOW", on_closing)
    root.mainloop()

if __name__ == "__main__":
    main() 