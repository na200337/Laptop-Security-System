"""
Smart Laptop Anti-Theft & Intrusion Detection System
Python lock-screen UI (talks to the Arduino Nano over USB)

Install:   pip install pyserial
Run:       python guard_ui.py

Create your own password hash:
    python -c "import hashlib; print(hashlib.sha256(b'MyPassword').hexdigest())"
"""

import ctypes
import hashlib
import hmac
import queue
import sys
import threading
import time
import tkinter as tk

import serial
from serial.tools import list_ports

# ======================= SETTINGS =======================
SERIAL_PORT = None          # None = auto-detect, or e.g. "COM3" / "/dev/ttyUSB0"
BAUD_RATE = 9600

# SHA-256 of the password. This default is "123456" -> CHANGE IT!
PASSWORD_SHA256 = "8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92"

LOCK_WORKSTATION_ON_ALARM = True   # Windows only: lock the OS on alarm

# Colors
COLOR_NORMAL = "#0f172a"   # dark blue
COLOR_WARNING = "#b91c1c"  # red
COLOR_ALARM = "#450a0a"    # dark red
# ========================================================


def find_arduino_port():
    """Look for a serial port that looks like an Arduino Nano (CH340/FTDI)."""
    keywords = ("arduino", "ch340", "usb-serial", "usb serial", "ftdi")
    for port in list_ports.comports():
        if any(k in (port.description or "").lower() for k in keywords):
            return port.device
    return None


def password_is_correct(text: str) -> bool:
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    return hmac.compare_digest(digest, PASSWORD_SHA256)


class GuardApp:
    def __init__(self):
        self.root = tk.Tk()
        self.root.withdraw()            # main window stays hidden
        self.win = None                 # lock screen (created on demand)
        self.events = queue.Queue()     # messages coming from the Arduino

        self.ser = self.connect()
        threading.Thread(target=self.read_loop, daemon=True).start()

        self.send("SYNC")               # ask Arduino for the current state
        self.root.after(100, self.process_events)

    # ------------------- serial communication -------------------
    def connect(self):
        port = SERIAL_PORT or find_arduino_port()
        if not port:
            sys.exit("Arduino not found. Set SERIAL_PORT in the settings.")
        ser = serial.Serial(port, BAUD_RATE, timeout=1)
        time.sleep(2)                   # the Nano resets when the port opens
        print(f"Connected to Arduino on {port}")
        return ser

    def send(self, message: str):
        self.ser.write((message + "\n").encode("utf-8"))

    def read_loop(self):
        """Background thread: read lines and put them in a queue."""
        while True:
            try:
                line = self.ser.readline().decode("utf-8", errors="ignore").strip()
            except serial.SerialException:
                self.events.put("EVT:DISCONNECTED")
                return
            if line:
                self.events.put(line)

    def process_events(self):
        """Runs in the UI thread every 100 ms."""
        while not self.events.empty():
            self.handle_event(self.events.get())
        self.root.after(100, self.process_events)

    # ------------------------ event logic ------------------------
    def handle_event(self, line: str):
        print("Arduino:", line)
        if line == "EVT:OPEN":
            self.show_login()
        elif line.startswith("EVT:FAIL:"):
            self.show_warning(line.split(":")[2])
        elif line == "EVT:ALARM":
            self.show_alarm()
        elif line in ("EVT:CLOSED", "EVT:UNLOCK"):
            self.hide()

    def submit(self):
        text = self.entry.get()
        self.entry.delete(0, "end")
        if password_is_correct(text):
            self.send("AUTH:OK")
            self.hide()
        else:
            self.send("AUTH:FAIL")

    # --------------------------- UI ---------------------------
    def build_window(self):
        win = tk.Toplevel(self.root)
        win.attributes("-fullscreen", True)
        win.attributes("-topmost", True)
        win.protocol("WM_DELETE_WINDOW", lambda: None)   # block the X button

        self.title = tk.Label(win, font=("Segoe UI", 40, "bold"), fg="white")
        self.title.pack(pady=(160, 10))
        self.message = tk.Label(win, font=("Segoe UI", 18), fg="white")
        self.message.pack(pady=10)

        self.entry = tk.Entry(win, show="*", font=("Segoe UI", 22),
                              justify="center", width=20)
        self.entry.pack(pady=20)
        self.entry.bind("<Return>", lambda _e: self.submit())

        self.button = tk.Button(win, text="Unlock", font=("Segoe UI", 16),
                                width=14, command=self.submit)
        self.button.pack(pady=10)

        self.win = win

    def paint(self, color, title, message, inputs_enabled=True):
        if self.win is None:
            self.build_window()
        for widget in (self.win, self.title, self.message):
            widget.configure(bg=color)
        self.title.configure(text=title)
        self.message.configure(text=message)

        state = "normal" if inputs_enabled else "disabled"
        self.entry.configure(state=state)
        self.button.configure(state=state)

        self.win.deiconify()
        self.win.lift()
        if inputs_enabled:
            self.entry.focus_force()

    def show_login(self):
        self.paint(COLOR_NORMAL, "LAPTOP LOCKED",
                   "Enter the password to continue")

    def show_warning(self, attempt):
        self.paint(COLOR_WARNING, "WARNING: WRONG PASSWORD",
                   f"Attempt {attempt}. The owner has been notified.")

    def show_alarm(self):
        self.paint(COLOR_ALARM, "ALARM - ACCESS DENIED",
                   "The owner is being called. This laptop is locked.",
                   inputs_enabled=False)
        if LOCK_WORKSTATION_ON_ALARM and sys.platform == "win32":
            ctypes.windll.user32.LockWorkStation()

    def hide(self):
        if self.win is not None:
            self.win.withdraw()

    def run(self):
        self.root.mainloop()


if __name__ == "__main__":
    GuardApp().run()
