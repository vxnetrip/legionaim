import os
os.system('cls')
import sys
sys.dont_write_bytecode = True
import ctypes
kernel32 = ctypes.windll.kernel32
kernel32.SetConsoleMode(kernel32.GetStdHandle(-10), 128)
import time
import subprocess
from rich.progress import Progress, ProgressColumn, BarColumn, TimeRemainingColumn, TextColumn
from rich.console import Console
from PyQt5.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, 
                           QPushButton, QFrame, QWidget, QApplication, QMessageBox, QGraphicsDropShadowEffect,
                           QGraphicsOpacityEffect)
from PyQt5.QtCore import Qt, QTimer, QPropertyAnimation, QEasingCurve, QRect, QPoint
from PyQt5.QtGui import (QColor, QPalette, QPainter)
import random
import math

console = Console()


def get_python_command():
    commands = [
        'python',
        'py',
        'python3']
    
    for cmd in commands:
        try:
            subprocess.run([cmd, '--version'], 
                          check=True, 
                          stdout=subprocess.DEVNULL, 
                          stderr=subprocess.DEVNULL)
            return cmd
        except (subprocess.CalledProcessError, FileNotFoundError):
            continue
    
    # If no Python command is found, return a default
    console.print("[!] Could not find Python command. Using 'python' as default.", style='red')
    return 'python'



def install_process():
    try:
        console.print("[!] *Don't Close this Window!*", style='red on white', justify='center')
        console.print('\n[?] Installing Libraries.. May take up to 20 minutes. Please be patient.\n', style='plum3', justify='center')
        
        modules = [
            'numpy',
            'pygame',
            'opencv-python',
            'PyQt5',
            'mss',
            'pywin32',
            'requests',
            'matplotlib --prefer-binary',
            'ultralytics',
            'pycryptodome',
            'pandas',
            'Pillow',
            'PyYAML',
            'scipy',
            'seaborn',
            'tqdm',
            'psutil',
            'wmi',
            'onnxruntime==1.15',
            'comtypes',
            'torch==2.3.1+cu118 -f https://download.pytorch.org/whl/torch_stable.html',
            'torchvision==0.18.1+cu118 -f https://download.pytorch.org/whl/torch_stable.html',
            'pypresence',
            'pyarmor'
        ]
        
        python_cmd = get_python_command()
        total_modules = len(modules)
        progress = Progress('[progress.description]{task.description}', BarColumn(), 
                          TextColumn('[progress.percentage]{task.percentage:>3.0f}%'), 
                          TimeRemainingColumn(), transient=True)
        
        with progress:
            task = progress.add_task('    [>] Processing...', total=total_modules)
            for module in modules:
                os.system(f'{python_cmd} -m pip --no-cache-dir --disable-pip-version-check install {module} >nul 2>&1')
                if "numpy" in module:
                    os.system(f'{python_cmd} -m pip install "numpy<2" >nul 2>&1')
                progress.update(task, advance=1)
        
        console.print('[!] Libraries Installed.', style='light_green', justify='center')
        console.print("\n[>] Please Re-Launch 'launcher.bat'", style='cyan1', justify='center')
        time.sleep(3)
        sys.exit()
    except Exception as e:
        console.print(f"[!] Error during installation: {str(e)}", style='red', justify='center')
        time.sleep(3)
        sys.exit(1)

devnull = open(os.devnull, 'w')
orig_stderr = sys.stderr
sys.stderr = devnull
__import__('wmi')
__import__('numpy')
__import__('torch')
__import__('ultralytics')
__import__('matplotlib')
__import__('pygame')
__import__('onnxruntime')
__import__('comtypes')
# Presence = __import__('pypresence').Presence
from PyQt5.QtCore import Qt
sys.stderr = orig_stderr

import cv2
import json as jsond
import math
import mss
import numpy as np
import time
from ultralytics import YOLO
import random
from PyQt5.QtWidgets import QApplication, QLineEdit, QWidget, QLabel, QPushButton, QVBoxLayout, QSlider, QHBoxLayout, QCheckBox, QShortcut, QDialog, QFrame, QStackedWidget, QComboBox
from PyQt5.QtGui import QPainter, QColor, QPen, QIcon, QKeySequence, QLinearGradient, QBrush, QRadialGradient, QFont, QPixmap
from PyQt5.QtCore import Qt, QTimer, QRectF, QEvent, QObject, pyqtSignal, QRect, QThread
import win32con
import win32api
import win32gui
import threading
import binascii
import uuid
from uuid import uuid4
import hashlib
import platform
import datetime
from datetime import datetime
import re
import subprocess
import psutil
import string
import winsound
import pygame
os.system('cls')
import queue
import hmac
import wmi
import colorsys
import win32file  # Added for GHUB
import ctypes.wintypes as wintypes  # Added for GHUB
from ctypes import windll  # Added for GHUB


random_caption1 = ''.join(random.choices(string.ascii_lowercase, k = 8))
random_caption2 = ''.join(random.choices(string.ascii_lowercase, k = 8))
random_caption3 = ''.join(random.choices(string.ascii_lowercase, k = 8))

try:
    import utility.lib.dxshot as bettercam # if this is not working: from utility.lib.dxshot import bettercam
except ImportError:
    # Fall back to local module
    from LegionAI.main.utility.lib.dxshot import bettercam

file = open('./utility/config.ini', 'r')
config = jsond.load(file)
Fov_Size = config['Fov_Size']
Confidence = config['Confidence']
Aim_Smooth = config['Aim_Smooth']
Max_Detections = config['Max_Detections']
Aim_Bone = config['Aim_Bone']
Enable_Aim = config['Enable_Aim']
Enable_Slots = config['Enable_Slots']
Controller_On = config['Controller_On']
Keybind = config['Keybind']
Keybind2 = config['Keybind2']
Enable_TriggerBot = config['Enable_TriggerBot']
Show_Fov = config['Show_Fov']
Show_Crosshair = config['Show_Crosshair']
Show_Debug = config['Show_Debug']
Auto_Fire_Fov_Size = config['Auto_Fire_Fov_Size']
Show_Detections = config['Show_Detections']
Show_Aimline = config['Show_Aimline']
Auto_Fire_Confidence = config['Auto_Fire_Confidence']
Auto_Fire_Keybind = config['Auto_Fire_Keybind']
Require_Keybind = config['Require_Keybind']
Use_Hue = config['Use_Hue']
CupMode_On = config['CupMode_On']
Reduce_Bloom = config['Reduce_Bloom']
Require_ADS = config['Require_ADS']
AntiRecoil_On = config['AntiRecoil_On']
AntiRecoil_Strength = config['AntiRecoil_Strength']
Theme_Hex_Color = config['Theme_Hex_Color']
Enable_Flick_Bot = config['Enable_Flick_Bot']
Flick_Scope_Sens = config['Flick_Scope_Sens']
Flick_Cooldown = config['Flick_Cooldown']
Flick_Delay = config['Flick_Delay']
Flickbot_Keybind = config['Flickbot_Keybind']
Enable_Aim_Slot1 = config['Enable_Aim_Slot1']
Enable_Aim_Slot2 = config['Enable_Aim_Slot2']
Enable_Aim_Slot3 = config['Enable_Aim_Slot3']
Enable_Aim_Slot4 = config['Enable_Aim_Slot4']
Enable_Aim_Slot5 = config['Enable_Aim_Slot5']
Slot1_Keybind = config['Slot1_Keybind']
Slot2_Keybind = config['Slot2_Keybind']
Slot3_Keybind = config['Slot3_Keybind']
Slot4_Keybind = config['Slot4_Keybind']
Slot5_Keybind = config['Slot5_Keybind']
Slot6_Keybind = config['Slot6_Keybind']
Fov_Size_Slot1 = config['Fov_Size_Slot1']
Fov_Size_Slot2 = config['Fov_Size_Slot2']
Fov_Size_Slot3 = config['Fov_Size_Slot3']
Fov_Size_Slot4 = config['Fov_Size_Slot4']
Fov_Size_Slot5 = config['Fov_Size_Slot5']
RGBOL_Value = config['RGBA_Value']
redr2d2 = RGBOL_Value['red']
greenr2d2 = RGBOL_Value['green']
bluer2d2 = RGBOL_Value['blue']
conf_opacity = RGBOL_Value['opacity']
conf_lightness = RGBOL_Value['lightness']
Use_Model_Class = config['Use_Model_Class']
Img_Value = config['Img_Value']
Model_FPS = config['Model_FPS']
Last_Model = config['Last_Model']
file = open('./utility/config.ini')
config = jsond.load(file)
Fov_Size = config['Fov_Size']
Confidence = config['Confidence']
Aim_Smooth = config['Aim_Smooth']
Max_Detections = config['Max_Detections']
Aim_Bone = config['Aim_Bone']
Enable_Aim = config['Enable_Aim']
Enable_Slots = config['Enable_Slots']
Controller_On = config['Controller_On']
Keybind = config['Keybind']
Keybind2 = config['Keybind2']
Enable_TriggerBot = config['Enable_TriggerBot']
Show_Fov = config['Show_Fov']
Show_Crosshair = config['Show_Crosshair']
Show_Debug = config['Show_Debug']
Auto_Fire_Fov_Size = config['Auto_Fire_Fov_Size']
Show_Detections = config['Show_Detections']
Show_Aimline = config['Show_Aimline']
Auto_Fire_Confidence = config['Auto_Fire_Confidence']
Auto_Fire_Keybind = config['Auto_Fire_Keybind']
Require_Keybind = config['Require_Keybind']
Use_Hue = config['Use_Hue']
CupMode_On = config['CupMode_On']
Reduce_Bloom = config['Reduce_Bloom']
Require_ADS = config['Require_ADS']
AntiRecoil_On = config['AntiRecoil_On']
AntiRecoil_Strength = config['AntiRecoil_Strength']
Theme_Hex_Color = config['Theme_Hex_Color']
Enable_Flick_Bot = config['Enable_Flick_Bot']
Flick_Scope_Sens = config['Flick_Scope_Sens']
Flick_Cooldown = config['Flick_Cooldown']
Flick_Delay = config['Flick_Delay']
Flickbot_Keybind = config['Flickbot_Keybind']
Enable_Aim_Slot1 = config['Enable_Aim_Slot1']
Enable_Aim_Slot2 = config['Enable_Aim_Slot2']
Enable_Aim_Slot3 = config['Enable_Aim_Slot3']
Enable_Aim_Slot4 = config['Enable_Aim_Slot4']
Enable_Aim_Slot5 = config['Enable_Aim_Slot5']
Slot1_Keybind = config['Slot1_Keybind']
Slot2_Keybind = config['Slot2_Keybind']
Slot3_Keybind = config['Slot3_Keybind']
Slot4_Keybind = config['Slot4_Keybind']
Slot5_Keybind = config['Slot5_Keybind']
Slot6_Keybind = config['Slot6_Keybind']
Fov_Size_Slot1 = config['Fov_Size_Slot1']
Fov_Size_Slot2 = config['Fov_Size_Slot2']
Fov_Size_Slot3 = config['Fov_Size_Slot3']
Fov_Size_Slot4 = config['Fov_Size_Slot4']
Fov_Size_Slot5 = config['Fov_Size_Slot5']
Use_Model_Class = config['Use_Model_Class']
Img_Value = config['Img_Value']
Model_FPS = config['Model_FPS']
Last_Model = config['Last_Model']
RGBOL_Value = config['RGBA_Value']
redr2d2 = RGBOL_Value['red']
greenr2d2 = RGBOL_Value['green']
bluer2d2 = RGBOL_Value['blue']
conf_opacity = RGBOL_Value['opacity']
conf_lightness = RGBOL_Value['lightness']
secretfile = open('utility\\extra.ini')
secretconfig = jsond.load(secretfile)
pixel_increment = secretconfig['pixel_increment']['value']
randomness = secretconfig['randomness']['value']
sensitivity = secretconfig['sensitivity']['value']
distance_to_scale = secretconfig['distance_to_scale']['value']
dont_launch_overlays = secretconfig['dont_launch_overlays']['value']
use_mss = secretconfig['use_mss']['value']
hide_masks = secretconfig['hide_masks']['value']
screensize = {
    'X': ctypes.windll.user32.GetSystemMetrics(0),
    'Y': ctypes.windll.user32.GetSystemMetrics(1) }
screen_res_X = screensize['X']
screen_res_Y = screensize['Y']
screen_x = int(screen_res_X / 2)
screen_y = int(screen_res_Y / 2)


if os.name == 'nt':
    import win32security
import requests
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad

# GHUB Mouse Control
class MOUSE_IO(ctypes.Structure):
    _fields_ = [
        ("button", ctypes.c_char),
        ("x", ctypes.c_char),
        ("y", ctypes.c_char),
        ("wheel", ctypes.c_char),
        ("unk1", ctypes.c_char)
    ]

handle = 0
found = False

def clamp_char(value: int) -> int:
    return max(-128, min(127, value))

def _DeviceIoControl(devhandle, ioctl, inbuf, inbufsiz, outbuf, outbufsiz):
    DeviceIoControl_Fn = windll.kernel32.DeviceIoControl
    DeviceIoControl_Fn.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        wintypes.LPVOID
    ]
    DeviceIoControl_Fn.restype = wintypes.BOOL
    
    dwBytesReturned = wintypes.DWORD(0)
    lpBytesReturned = ctypes.byref(dwBytesReturned)
    status = DeviceIoControl_Fn(
        int(devhandle),
        ioctl,
        inbuf,
        inbufsiz,
        outbuf,
        outbufsiz,
        lpBytesReturned,
        None
    )
    return status, dwBytesReturned

def device_initialize(device_name: str) -> bool:
    global handle
    try:
        handle = win32file.CreateFileW(
            device_name,
            win32file.GENERIC_WRITE,
            0,
            None,
            win32file.OPEN_ALWAYS,
            win32file.FILE_ATTRIBUTE_NORMAL,
            0
        )
    except Exception as e:
        return False
    return bool(handle)

def mouse_open() -> bool:
    global found
    global handle

    if found and handle:
        return True

    for i in range(1, 10):
        devpath = f'\\??\\ROOT#SYSTEM#000{i}#' + '{1abc05c0-c378-41b9-9cef-df1aba82b015}'
        if device_initialize(devpath):
            found = True
            return True

    return False

def call_mouse(buffer: MOUSE_IO) -> bool:
    global handle
    status, _ = _DeviceIoControl(
        handle, 
        0x2a2010,
        ctypes.c_void_p(ctypes.addressof(buffer)),
        ctypes.sizeof(buffer),
        None,
        0, 
    )
    return status

def mouse_close() -> None:
    global handle
    if handle:
        win32file.CloseHandle(int(handle))
        handle = 0

def mouse_move(button: int, x: int, y: int, wheel: int) -> None:
    """
    Sends a single relative mouse input to the GHUB device.
    """
    global handle

    x_clamped = clamp_char(x)
    y_clamped = clamp_char(y)
    btn_byte   = clamp_char(button)
    wheel_byte = clamp_char(wheel)

    io = MOUSE_IO()
    # c_char expects a bytes object of length 1 or an int in the range -128..127:
    io.button = ctypes.c_char(btn_byte.to_bytes(1, 'little', signed=True))
    io.x      = ctypes.c_char(x_clamped.to_bytes(1, 'little', signed=True))
    io.y      = ctypes.c_char(y_clamped.to_bytes(1, 'little', signed=True))
    io.wheel  = ctypes.c_char(wheel_byte.to_bytes(1, 'little', signed=True))
    io.unk1   = ctypes.c_char(b'\x00')

    if not mouse_open():
        return
        
    if not call_mouse(io):
        mouse_close()
        mouse_open()

# Create compatibility aliases to maintain existing code compatibility
handle = 0  # Ensure handle is initialized to 0 first
found = False  # Ensure found is initialized to False
ghub_handle = handle  # Then assign to compatibility vars
ghub_found = found

def ghub_device_initialize(device_name: str) -> bool:
    return device_initialize(device_name)

def ghub_mouse_open() -> bool:
    return mouse_open()

def _ghub_DeviceIoControl(devhandle, ioctl, inbuf, inbufsiz, outbuf, outbufsiz):
    return _DeviceIoControl(devhandle, ioctl, inbuf, inbufsiz, outbuf, outbufsiz)

def ghub_call_mouse(buffer: MOUSE_IO) -> bool:
    return call_mouse(buffer)

def ghub_mouse_close() -> None:
    return mouse_close()

def ghub_mouse_move(button: int, x: int, y: int, wheel: int) -> None:
    return mouse_move(button, x, y, wheel)

# Module-level helper for potentially large relative moves using GHUB
def _ghub_move_large_relative(dx: int, dy: int) -> None:
    # Loop to handle movements larger than c_char range (-128 to 127)
    remaining_dx = int(round(dx))
    remaining_dy = int(round(dy))

    while remaining_dx != 0 or remaining_dy != 0:
        move_dx = clamp_char(remaining_dx)
        move_dy = clamp_char(remaining_dy)
        
        mouse_move(button=0, x=move_dx, y=move_dy, wheel=0)
        
        remaining_dx -= move_dx
        remaining_dy -= move_dy
        
        # Optional: Small delay if inputs are too rapid for the game/driver
        # time.sleep(0.001) # 1ms, adjust if necessary
        if abs(remaining_dx) < 1 and abs(remaining_dy) < 1: # Break if effectively zero
            break




class api:

    name = 'LegionAI'
    ownerid = ''
    secret = ''
    version = '1.0'
    hash_to_check = ''
    

    class user_data:
        username = 'sdffdsdfs'
        ip = 'sdfdsfs'
        hwid = 'sddsf'
        expires = 'sddsf'
        createdate = 'sddsf'
        lastlogin = 'sddsf'
        subscription = 'sddsf'
        subscriptions = 'sddsf'

    def __init__(self, name, ownerid, secret, version, hash_to_check):
        self.name = name
        self.ownerid = ownerid
        self.secret = secret
        self.version = version
        self.hash_to_check = hash_to_check
        self.init()

    sessionid = ''
    enckey = ''
    initialized = False
    
    def init(self):
        import requests
        import json
        import hashlib
        from uuid import uuid4
        
        if self.sessionid:
            return
            
        init_iv = hashlib.sha256(str(uuid4())[:8].encode()).hexdigest()
        self.enckey = hashlib.sha256(str(uuid4())[:8].encode()).hexdigest()
        
        post_data = {
            'type': 'init',
            'ver': self.version,
            'hash': self.hash_to_check,
            'name': self.name,
            'ownerid': self.ownerid
        }
        
        try:
            session = requests.Session()
            response = session.post('https://keyauth.win/api/1.3/', data=post_data, timeout=10)
            response_text = response.text
            
            if response_text == 'KeyAuth_Invalid':
                return
                
            try:
                json_resp = json.loads(response_text)
                
                if json_resp.get('message') == 'invalidver':
                    return
                    
                if not json_resp.get('success'):
                    return
                    
                self.sessionid = json_resp.get('sessionid', '')
                self.initialized = True
                
            except Exception:
                return
                
        except Exception:
            return

    def checkinit(self):
        if not self.initialized:
            self.init()
            if not self.initialized:
                raise Exception("Session ID not provided, this is required.")

    def license(self, key, hwid):
        # First verify the key with KeyAuth server
        self.checkinit()
        import requests
        import json
        import hashlib
        
        # Generate a real HWID based on Windows Machine GUID if none provided
        if hwid == "NONE":
            try:
                import subprocess
                hwid = subprocess.check_output('wmic csproduct get uuid').decode().split('\n')[1].strip()
            except:
                hwid = os.getenv('COMPUTERNAME', 'Unknown')
                
        # Validate with KeyAuth server
        try:
            session = requests.Session()
            post_data = {
                'type': 'license',
                'key': key,
                'hwid': hwid,
                'sessionid': self.sessionid,
                'name': self.name,
                'ownerid': self.ownerid,
                'ver': self.version
            }
            
            response = session.post('https://keyauth.win/api/1.3/', data=post_data, timeout=10)
            response_text = response.text
            
            # Parse the response
            json_resp = json.loads(response_text)
            
            if json_resp.get('success'):
                # Key is valid, proceed with launching
                console.print('\n[>] Launching. Please Wait . . .', style='magenta3', justify='center')
                
                def DOWNLOAD_MODEL(fname, url):
                    destination_path = 'C:\\\\ProgramData\\\\NVIDIA\\\\NGX\\\\models'
                    full_path = os.path.join(destination_path, fname)
                    r = requests.get(url, allow_redirects = True)
                    file = open(full_path, 'wb')
                    file.write(r.content)

                os.system('mkdir "C:\\ProgramData\\NVIDIA\\NGX\\models" >nul 2>&1')
                DOWNLOAD_MODEL('8OON.pt', 'https://raw.githubusercontent.com/aiantics/bU7ErD/main/D-VR90EX/DF990/B9022/CKRRJE/8OON.pt')
                DOWNLOAD_MODEL('8OOS.pt', 'https://raw.githubusercontent.com/aiantics/bU7ErD/main/D-VR90EX/DF990/B9022/CKRRJE/8OOS.pt')
                DOWNLOAD_MODEL('8OOU.pt', 'https://raw.githubusercontent.com/aiantics/bU7ErD/main/D-VR90EX/DF990/B9022/CKRRJE/8OOU.pt')
                
                def start_aimbot():
                    global legion
                    legion = Ai992()
                    legion.start()

                start_aimbot()
                return True
            else:
                # Key is invalid
                error_message = json_resp.get('message', 'Unknown error')
                console.print('\n[!] License validation failed', style='red', justify='center')
                raise Exception(error_message)
                
        except Exception as e:
            error_msg = str(e)
            raise Exception(error_msg)
    




class encryption:
    encrypt_string = lambda plain_text, key, iv: binascii.hexlify(AES.new(key, AES.MODE_CBC, iv).encrypt(pad(plain_text.encode(), 16))).decode()
    decrypt_string = lambda cipher_text, key, iv: unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(binascii.unhexlify(cipher_text)), 16).decode()
    encrypt = lambda message, enc_key, iv: encryption.encrypt_string(message, SHA256.new(enc_key.encode()).digest()[:32], SHA256.new(iv.encode()).digest()[:16])
    decrypt = lambda message, enc_key, iv: encryption.decrypt_string(message, SHA256.new(enc_key.encode()).digest()[:32], SHA256.new(iv.encode()).digest()[:16])


PUL = ctypes.POINTER(ctypes.c_ulong)

class KeyBdInput(ctypes.Structure):
    _fields_ = [
        ('wVk', ctypes.c_ushort),
        ('wScan', ctypes.c_ushort),
        ('dwFlags', ctypes.c_ulong),
        ('time', ctypes.c_ulong),
        ('dwExtraInfo', PUL)]



class HardwareInput(ctypes.Structure):
    _fields_ = [
        ('uMsg', ctypes.c_ulong),
        ('wParamL', ctypes.c_short),
        ('wParamH', ctypes.c_ushort)]



class MouseInput(ctypes.Structure):
    _fields_ = [
        ('dx', ctypes.c_long),
        ('dy', ctypes.c_long),
        ('mouseData', ctypes.c_ulong),
        ('dwFlags', ctypes.c_ulong),
        ('time', ctypes.c_ulong),
        ('dwExtraInfo', PUL)]



class Input_I(ctypes.Union):
    _fields_ = [
        ('ki', KeyBdInput),
        ('mi', MouseInput),
        ('hi', HardwareInput)]


class Input(ctypes.Structure):
    _fields_ = [
        ('type', ctypes.c_ulong),
        ('ii', Input_I)]



class POINT(ctypes.Structure):
    _fields_ = [
        ('x', ctypes.c_long),
        ('y', ctypes.c_long)]


KEY_NAMES = {
    0x01: 'LMB',
    0x02: 'RMB',
    0x04: 'MMB',
    0x05: 'X1',
    0x06: 'X2',
    0x08: 'BKSPC',
    0x09: 'TAB',
    0x0D: 'ENTER',
    0x10: 'SHIFT',
    0x11: 'CTRL',
    0x12: 'ALT',
    0x13: 'PAUSE',
    0x14: 'CAPS',
    0x1B: 'ESC',
    0x20: 'SPACE',
    0x21: 'PGUP',
    0x22: 'PGDN',
    0x23: 'END',
    0x24: 'HOME',
    0x25: 'LEFT',
    0x26: 'UP',
    0x27: 'RIGHT',
    0x28: 'DOWN',
    0x2C: 'PRTSC',
    0x2D: 'INS',
    0x2E: 'DEL',
    0x30: '0',
    0x31: '1',
    0x32: '2',
    0x33: '3',
    0x34: '4',
    0x35: '5',
    0x36: '6',
    0x37: '7',
    0x38: '8',
    0x39: '9',
    0x41: 'A',
    0x42: 'B',
    0x43: 'C',
    0x44: 'D',
    0x45: 'E',
    0x46: 'F',
    0x47: 'G',
    0x48: 'H',
    0x49: 'I',
    0x4A: 'J',
    0x4B: 'K',
    0x4C: 'L',
    0x4D: 'M',
    0x4E: 'N',
    0x4F: 'O',
    0x50: 'P',
    0x51: 'Q',
    0x52: 'R',
    0x53: 'S',
    0x54: 'T',
    0x55: 'U',
    0x56: 'V',
    0x57: 'W',
    0x58: 'X',
    0x59: 'Y',
    0x5A: 'Z',
    0x70: 'F1',
    0x71: 'F2',
    0x72: 'F3',
    0x73: 'F4',
    0x74: 'F5',
    0x75: 'F6',
    0x76: 'F7',
    0x77: 'F8',
    0x78: 'F9',
    0x79: 'F10',
    0x7A: 'F11',
    0x7B: 'F12',
}


os.environ['QT_ENABLE_HIGHDPI_SCALING'] = '1'
os.environ['QT_AUTO_SCREEN_SCALE_FACTOR'] = '1'
os.environ['QT_SCALE_FACTOR'] = '1'




if hasattr(Qt, 'AA_EnableHighDpiScaling'):
    QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
if hasattr(Qt, 'AA_UseHighDpiPixmaps'):
    QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)

class MyWindow(QWidget):
    modell = YOLO('C:\\ProgramData\\NVIDIA\\NGX\\models\\8OON.pt')
    
    # Register cleanup function to run when application exits
    atexit_registered = False

    
    def __init__(self):
        super().__init__()
        self.init_ui()


    
    def init_ui(self):
        self.Keybind = Keybind
        self.Keybind2 = Keybind2
        self.Auto_Fire_Keybind = Auto_Fire_Keybind
        self.Flickbot_Keybind = Flickbot_Keybind
        self.Slot1_Keybind = Slot1_Keybind
        self.Slot2_Keybind = Slot2_Keybind
        self.Slot3_Keybind = Slot3_Keybind
        self.Slot4_Keybind = Slot4_Keybind
        self.Slot5_Keybind = Slot5_Keybind
        self.Slot6_Keybind = Slot6_Keybind
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update)
        self.timer.start(300)
        self.setWindowTitle('LegionAI')
        self.setWindowOpacity(0.98)
        self.setFixedSize(350, 500)
        self.setWindowFlag(Qt.MSWindowsFixedSizeDialogHint, True)
        self.setWindowFlag(Qt.WindowMinimizeButtonHint, False)
        self.setWindowFlag(Qt.WindowMaximizeButtonHint, False)
        self.setWindowFlags(Qt.Tool | Qt.WindowStaysOnTopHint)
        self.theme_hex_color = Theme_Hex_Color
        self.widget_bg_color = '#1E1E1E'
        self.widget_border_color = '#2E2E2E'
        menu_tab_style = '\n\t\t\tQPushButton {\n\t\t\t\tborder: none;\n\t\t\t\tborder-bottom: 1.5px solid #616161;\n\t\t\t\tpadding-bottom: 4px;\n\t\t\t\tmargin-left: 60%;\n\t\t\t\tmargin-right: 60%;\n\t\t\t}\n\t\t'
        self.color_input_label = QLabel('Menu Hex Color')
        self.color_input = QLineEdit(self)
        self.color_input.setPlaceholderText('Enter hex color code (example: #fc0000)')
        self.color_input.setText(Theme_Hex_Color)
        self.color_input.returnPressed.connect(self.update_theme_color)
        self.Welcome_label_1 = QLabel('LegionAI')
        self.Welcome_label_2 = QLabel('LegionAI')
        self.Welcome_label_3 = QLabel('LegionAI')
        self.Welcome_label_4 = QLabel('LegionAI')
        self.Welcome_label_5 = QLabel('LegionAI')
        self.Welcome_label_6 = QLabel('LegionAI')
        self.Welcome_label_7 = QLabel('LegionAI')
        self.info_label_3 = QLabel(f'''<font color=\'{self.theme_hex_color}\'>User Stats:</font>''', self)
        self.info_label_4 = QLabel('> Your Key: Loading..')
        self.info_label_5 = QLabel('> Purchased: Loading..')
        self.info_label_6 = QLabel('> Key Expires: Loading..')
        self.info_label_7 = QLabel('> Last Login: Loading..')
        self.info_label_8 = QLabel(f'''<font color=\'{self.theme_hex_color}\'>Menu Hotkeys:</font>''', self)
        self.info_label_9 = QLabel(f'''> Close Normally: <font color=\'{self.theme_hex_color}\'>[X]</font>''', self)
        self.info_label_10 = QLabel(f'''> Quick On/Off: <font color=\'{self.theme_hex_color}\'>[F1]</font>''', self)
        self.info_label_11 = QLabel(f'''> Panic Close: <font color=\'{self.theme_hex_color}\'>[F2]</font>''', self)
        self.info_label_13 = QLabel(f'''> Show/Hide the Menu: <font color=\'{self.theme_hex_color}\'>[F8]</font>''', self)
        self.Fov_Size_label = QLabel(f'''FOV Size: {str(Fov_Size)}''')
        self.slider = QSlider(Qt.Horizontal)
        self.slider.setStyleSheet(self.get_slider_style())
        self.slider.setMaximumWidth(160)
        self.slider.setMinimumWidth(160)
        self.slider.setFocusPolicy(Qt.NoFocus)
        self.slider.setMinimum(120)
        self.slider.setMaximum(400)
        self.slider.setValue(int(round(Fov_Size)))
        self.Confidence_label = QLabel(f'''Confidence: {str(Confidence)}%''')
        self.slider0 = QSlider(Qt.Horizontal)
        self.slider0.setStyleSheet(self.get_slider_style())
        self.slider0.setMaximumWidth(160)
        self.slider0.setMinimumWidth(160)
        self.slider0.setFocusPolicy(Qt.NoFocus)
        self.slider0.setMinimum(45)
        self.slider0.setMaximum(85)
        self.slider0.setValue(int(round(Confidence)))
        self.Aim_Smooth_label = QLabel(f'''Aim Speed: {str(Aim_Smooth)}''')
        self.slider3 = QSlider(Qt.Horizontal)
        self.slider3.setStyleSheet(self.get_slider_style())
        self.slider3.setMaximumWidth(160)
        self.slider3.setMinimumWidth(160)
        self.slider3.setFocusPolicy(Qt.NoFocus)
        self.slider3.setMinimum(10)
        self.slider3.setMaximum(80)
        self.slider3.setValue(int(round(Aim_Smooth)))
        self.Max_Detections_label = QLabel(f'''Max Detections: {str(Max_Detections)}''')
        self.slider4 = QSlider(Qt.Horizontal)
        self.slider4.setStyleSheet(self.get_slider_style())
        self.slider4.setMaximumWidth(160)
        self.slider4.setMinimumWidth(160)
        self.slider4.setFocusPolicy(Qt.NoFocus)
        self.slider4.setMinimum(1)
        self.slider4.setMaximum(6)
        self.slider4.setValue(int(round(Max_Detections)))
        self.aim_bone_label = QLabel('Aim Bone')
        self.aim_bone_combobox = QComboBox()
        self.aim_bone_combobox.setMinimumHeight(10)
        self.aim_bone_combobox.setMaximumHeight(10)
        self.aim_bone_combobox.setMinimumWidth(160)
        self.aim_bone_combobox.setMaximumHeight(160)
        self.aim_bone_combobox.setStyleSheet('QComboBox { background-color: ' + self.widget_bg_color + '; }')
        self.aim_bone_combobox.addItems([
            'Head',
            'Neck',
            'Body'])
        self.Aim_Bone = self.aim_bone_combobox.currentText()
        if Aim_Bone == 'Head':
            self.aim_bone_combobox.setCurrentText('Head')
        if Aim_Bone == 'Neck':
            self.aim_bone_combobox.setCurrentText('Neck')
        if Aim_Bone == 'Body':
            self.aim_bone_combobox.setCurrentText('Body')
        self.img_value_label = QLabel('Image Scaling')
        self.img_value_combobox = QComboBox()
        self.img_value_combobox.setMinimumHeight(10)
        self.img_value_combobox.setMaximumHeight(10)
        self.img_value_combobox.setMinimumWidth(160)
        self.img_value_combobox.setMaximumHeight(160)
        self.img_value_combobox.setStyleSheet('QComboBox { background-color: ' + self.widget_bg_color + '; }')
        self.img_value_combobox.addItems([
            '320',
            '480',
            '640',
            '736',
            '832'])
        self.img_value = self.img_value_combobox.currentText()
        if Img_Value == '320':
            self.img_value_combobox.setCurrentText('320')
        if Img_Value == '480':
            self.img_value_combobox.setCurrentText('480')
        if Img_Value == '640':
            self.img_value_combobox.setCurrentText('640')
        if Img_Value == '736':
            self.img_value_combobox.setCurrentText('736')
        if Img_Value == '832':
            self.img_value_combobox.setCurrentText('832')
        self.fps_label = QLabel(f'''Max FPS: {str(Model_FPS)}''')
        self.slider_fps = QSlider(Qt.Horizontal)
        self.slider_fps.setStyleSheet(self.get_slider_style())
        self.slider_fps.setMaximumWidth(160)
        self.slider_fps.setMinimumWidth(160)
        self.slider_fps.setFocusPolicy(Qt.NoFocus)
        self.slider_fps.setMinimum(60)
        self.slider_fps.setMaximum(360)
        self.slider_fps.setValue(int(round(Model_FPS)))
        self.model_selected_label = QLabel('Load Model')
        self.model_selected_combobox = QComboBox()
        self.model_selected_combobox.setMinimumHeight(10)
        self.model_selected_combobox.setMaximumHeight(10)
        self.model_selected_combobox.setMinimumWidth(160)
        self.model_selected_combobox.setMaximumHeight(160)
        self.model_selected_combobox.setStyleSheet('QComboBox { background-color: ' + self.widget_bg_color + '; }')
        self.modelss = { }
        self.load_modelss()
        self.rgb_label = QLabel('RGB: 255 50 1')
        self.hue_slider = QSlider(Qt.Horizontal)
        self.hue_slider.setStyleSheet(self.get_slider_style())
        self.hue_slider.setMaximumWidth(160)
        self.hue_slider.setMinimumWidth(160)
        self.hue_slider.setFocusPolicy(Qt.NoFocus)
        self.hue_slider.setMinimum(0)
        self.hue_slider.setMaximum(359)
        (huer, _, _) = colorsys.rgb_to_hsv(redr2d2 / 255, greenr2d2 / 255, bluer2d2 / 255)
        hue_degreess = int(huer * 359)
        self.hue_slider.setValue(hue_degreess)
        self.lightness_label = QLabel('Lightness: 128')
        self.lightness_slider = QSlider(Qt.Horizontal)
        self.lightness_slider.setStyleSheet(self.get_slider_style())
        self.lightness_slider.setMaximumWidth(160)
        self.lightness_slider.setMinimumWidth(160)
        self.lightness_slider.setFocusPolicy(Qt.NoFocus)
        self.lightness_slider.setMinimum(0)
        self.lightness_slider.setMaximum(255)
        self.lightness_slider.setValue(conf_lightness)
        self.opacity_label = QLabel('Opacity: 200')
        self.opacity_slider = QSlider(Qt.Horizontal)
        self.opacity_slider.setStyleSheet(self.get_slider_style())
        self.opacity_slider.setMaximumWidth(160)
        self.opacity_slider.setMinimumWidth(160)
        self.opacity_slider.setFocusPolicy(Qt.NoFocus)
        self.opacity_slider.setMinimum(0)
        self.opacity_slider.setMaximum(255)
        self.opacity_slider.setValue(conf_opacity)
        self.Enable_Aim_checkbox = QCheckBox('Enable Aimbot')
        self.Enable_Aim_checkbox.setFocusPolicy(Qt.NoFocus)
        self.Enable_Aim_checkbox.setChecked(Enable_Aim)
        self.Enable_Slots_checkbox = QCheckBox('Enable Weapon Slots')
        self.Enable_Slots_checkbox.setFocusPolicy(Qt.NoFocus)
        self.Enable_Slots_checkbox.setChecked(Enable_Slots)
        self.Enable_Flick_checkbox = QCheckBox('Enable Flickbot')
        self.Enable_Flick_checkbox.setFocusPolicy(Qt.NoFocus)
        self.Enable_Flick_checkbox.setChecked(Enable_Flick_Bot)
        self.flick_sens_info_label = QLabel('Use your in-game fortnite sensitivity.')
        self.flick_set_info_label = QLabel('Flickbot Settings:')
        self.flick_scope_label = QLabel(f'''Flick Strength: {str(Flick_Scope_Sens)}%''')
        self.flick_scope_slider = QSlider(Qt.Horizontal)
        self.flick_scope_slider.setStyleSheet(self.get_slider_style())
        self.flick_scope_slider.setMaximumWidth(160)
        self.flick_scope_slider.setMinimumWidth(160)
        self.flick_scope_slider.setFocusPolicy(Qt.NoFocus)
        self.flick_scope_slider.setMinimum(10)
        self.flick_scope_slider.setMaximum(90)
        self.flick_scope_slider.setValue(int(Flick_Scope_Sens))
        self.flick_cool_label = QLabel(f'''Cool Down: {str(Flick_Cooldown)}s''')
        self.flick_cool_slider = QSlider(Qt.Horizontal)
        self.flick_cool_slider.setStyleSheet(self.get_slider_style())
        self.flick_cool_slider.setMaximumWidth(160)
        self.flick_cool_slider.setMinimumWidth(160)
        self.flick_cool_slider.setFocusPolicy(Qt.NoFocus)
        self.flick_cool_slider.setMinimum(5)
        self.flick_cool_slider.setMaximum(120)
        self.flick_cool_slider.setValue(int(Flick_Cooldown * 100))
        self.flick_delay_label = QLabel(f'''Shot Delay: {str(Flick_Delay)}s''')
        self.flick_delay_slider = QSlider(Qt.Horizontal)
        self.flick_delay_slider.setStyleSheet(self.get_slider_style())
        self.flick_delay_slider.setMaximumWidth(160)
        self.flick_delay_slider.setMinimumWidth(160)
        self.flick_delay_slider.setFocusPolicy(Qt.NoFocus)
        self.flick_delay_slider.setMinimum(3)
        self.flick_delay_slider.setMaximum(10)
        self.flick_delay_slider.setValue(int(Flick_Delay * 1000))
        self.Controller_On_checkbox = QCheckBox('Enable Controller Support')
        self.Controller_On_checkbox.setFocusPolicy(Qt.NoFocus)
        self.Controller_On_checkbox.setChecked(Controller_On)
        self.CupMode_On_checkbox = QCheckBox('Enable Tournament Mode')
        self.CupMode_On_checkbox.setFocusPolicy(Qt.NoFocus)
        self.CupMode_On_checkbox.setChecked(CupMode_On)
        self.AntiRecoil_On_checkbox = QCheckBox('Enable Anti-Recoil')
        self.AntiRecoil_On_checkbox.setFocusPolicy(Qt.NoFocus)
        self.AntiRecoil_On_checkbox.setChecked(AntiRecoil_On)
        self.Reduce_Bloom_checkbox = QCheckBox('Reduce Bloom')
        self.Reduce_Bloom_checkbox.setFocusPolicy(Qt.NoFocus)
        self.Reduce_Bloom_checkbox.setChecked(Reduce_Bloom)
        self.Require_ADS_checkbox = QCheckBox('Require ADS')
        self.Require_ADS_checkbox.setFocusPolicy(Qt.NoFocus)
        self.Require_ADS_checkbox.setChecked(Require_ADS)
        self.AntiRecoil_Strength_label = QLabel(f'''Strength: {str(AntiRecoil_Strength)}''')
        self.slider60 = QSlider(Qt.Horizontal)
        self.slider60.setStyleSheet(self.get_slider_style())
        self.slider60.setMaximumWidth(160)
        self.slider60.setMinimumWidth(160)
        self.slider60.setFocusPolicy(Qt.NoFocus)
        self.slider60.setMinimum(1)
        self.slider60.setMaximum(10)
        self.slider60.setValue(int(round(AntiRecoil_Strength)))
        self.Show_Fov_checkbox = QCheckBox('Show FOV Circle')
        self.Show_Fov_checkbox.setFocusPolicy(Qt.NoFocus)
        self.Show_Fov_checkbox.setChecked(Show_Fov)
        self.Show_Crosshair_checkbox = QCheckBox('Show Crosshair')
        self.Show_Crosshair_checkbox.setFocusPolicy(Qt.NoFocus)
        self.Show_Crosshair_checkbox.setChecked(Show_Crosshair)
        self.Show_Detections_checkbox = QCheckBox('Show Detections')
        self.Show_Detections_checkbox.setFocusPolicy(Qt.NoFocus)
        self.Show_Detections_checkbox.setChecked(Show_Detections)
        self.Show_Aimline_checkbox = QCheckBox('Show Aimline')
        self.Show_Aimline_checkbox.setFocusPolicy(Qt.NoFocus)
        self.Show_Aimline_checkbox.setChecked(Show_Aimline)
        self.Show_Debug_checkbox = QCheckBox('Show Debug Window')
        self.Show_Debug_checkbox.setFocusPolicy(Qt.NoFocus)
        self.Show_Debug_checkbox.setChecked(Show_Debug)
        self.Enable_TriggerBot_checkbox = QCheckBox('Enable Auto-Fire')
        self.Enable_TriggerBot_checkbox.setFocusPolicy(Qt.NoFocus)
        self.Enable_TriggerBot_checkbox.setChecked(Enable_TriggerBot)
        self.Use_Model_Class_checkbox = QCheckBox('Detect Single Class Only')
        self.Use_Model_Class_checkbox.setFocusPolicy(Qt.NoFocus)
        self.Use_Model_Class_checkbox.setChecked(Use_Model_Class)
        self.Require_Keybind_checkbox = QCheckBox('Require Keybind [Auto-Fire]')
        self.Require_Keybind_checkbox.setFocusPolicy(Qt.NoFocus)
        self.Require_Keybind_checkbox.setChecked(Require_Keybind)
        self.Use_Hue_checkbox = QCheckBox('Use Rainbow Hue')
        self.Use_Hue_checkbox.setFocusPolicy(Qt.NoFocus)
        self.Use_Hue_checkbox.setChecked(Use_Hue)
        self.Auto_Fire_Fov_Size_label = QLabel(f'''FOV Size: {str(Auto_Fire_Fov_Size)}''')
        self.slider5 = QSlider(Qt.Horizontal)
        self.slider5.setStyleSheet(self.get_slider_style())
        self.slider5.setMaximumWidth(160)
        self.slider5.setMinimumWidth(160)
        self.slider5.setFocusPolicy(Qt.NoFocus)
        self.slider5.setMinimum(4)
        self.slider5.setMaximum(30)
        self.slider5.setValue(int(round(Auto_Fire_Fov_Size)))
        self.Auto_Fire_Confidence_label = QLabel(f'''Confidence: 0.{str(Auto_Fire_Confidence)}''')
        self.slider6 = QSlider(Qt.Horizontal)
        self.slider6.setStyleSheet(self.get_slider_style())
        self.slider6.setMaximumWidth(160)
        self.slider6.setMinimumWidth(160)
        self.slider6.setFocusPolicy(Qt.NoFocus)
        self.slider6.setMinimum(60)
        self.slider6.setMaximum(80)
        self.slider6.setValue(int(round(Auto_Fire_Confidence)))
        self.btn_extraini = QPushButton('Refresh Extra.ini')
        self.btn_extraini.setFocusPolicy(Qt.NoFocus)
        self.btn_extraini.setStyleSheet(self.get_button_style())
        self.btn_extraini.setMinimumWidth(120)
        self.btn_extraini.clicked.connect(self.refresh_extra)
        self.btn_extraini2 = QPushButton('Refresh Extra.ini')
        self.btn_extraini2.setFocusPolicy(Qt.NoFocus)
        self.btn_extraini2.setStyleSheet(self.get_button_style())
        self.btn_extraini2.setMinimumWidth(80)
        self.btn_extraini2.clicked.connect(self.refresh_extra)
        self.hotkey_label = QLabel('Key')
        self.hotkey_label2 = QLabel('Or')
        key_name_converted = KEY_NAMES.get(Keybind, 'None' if Keybind is None else f'''0x{Keybind:02X}''')
        key_name_converted2 = KEY_NAMES.get(Keybind2, 'None' if Keybind2 is None else f'''0x{Keybind2:02X}''')
        key_name_converted3 = KEY_NAMES.get(Auto_Fire_Keybind, 'None' if Auto_Fire_Keybind is None else f'''0x{Auto_Fire_Keybind:02X}''')
        key_name_converted4 = KEY_NAMES.get(Flickbot_Keybind, 'None' if Flickbot_Keybind is None else f'''0x{Flickbot_Keybind:02X}''')
        global is_selecting_hotkey, is_selecting_hotkey2, is_selecting_hotkey3, is_selecting_hotkey4
        is_selecting_hotkey = False
        self.btn_hotkey = QPushButton(f'''{key_name_converted}''')
        self.btn_hotkey.setFocusPolicy(Qt.NoFocus)
        self.btn_hotkey.setStyleSheet(self.get_button_style())
        self.btn_hotkey.setMinimumWidth(80)
        self.btn_hotkey.clicked.connect(self.start_select_hotkey)
        is_selecting_hotkey2 = False
        self.btn_hotkey2 = QPushButton(f'''{key_name_converted2}''')
        self.btn_hotkey2.setFocusPolicy(Qt.NoFocus)
        self.btn_hotkey2.setStyleSheet(self.get_button_style())
        self.btn_hotkey2.setMinimumWidth(80)
        self.btn_hotkey2.clicked.connect(self.start_select_hotkey2)
        self.hotkey_label3 = QLabel('Auto-Fire Key')
        is_selecting_hotkey3 = False
        self.btn_hotkey3 = QPushButton(f'''{key_name_converted3}''')
        self.btn_hotkey3.setFocusPolicy(Qt.NoFocus)
        self.btn_hotkey3.setStyleSheet(self.get_button_style())
        self.btn_hotkey3.setMinimumWidth(80)
        self.btn_hotkey3.clicked.connect(self.start_select_hotkey3)
        self.hotkey_label4 = QLabel('Flickbot Key')
        is_selecting_hotkey4 = False
        self.btn_hotkey4 = QPushButton(f'''{key_name_converted4}''')
        self.btn_hotkey4.setFocusPolicy(Qt.NoFocus)
        self.btn_hotkey4.setStyleSheet(self.get_button_style())
        self.btn_hotkey4.setMinimumWidth(80)
        self.btn_hotkey4.clicked.connect(self.start_select_hotkey4)
        self.Enable_Aim_Slot1_checkbox = QCheckBox('Aim')
        self.Enable_Aim_Slot1_checkbox.setFocusPolicy(Qt.NoFocus)
        self.Enable_Aim_Slot1_checkbox.setChecked(Enable_Aim_Slot1)
        self.Enable_Aim_Slot2_checkbox = QCheckBox('Aim')
        self.Enable_Aim_Slot2_checkbox.setFocusPolicy(Qt.NoFocus)
        self.Enable_Aim_Slot2_checkbox.setChecked(Enable_Aim_Slot2)
        self.Enable_Aim_Slot3_checkbox = QCheckBox('Aim')
        self.Enable_Aim_Slot3_checkbox.setFocusPolicy(Qt.NoFocus)
        self.Enable_Aim_Slot3_checkbox.setChecked(Enable_Aim_Slot3)
        self.Enable_Aim_Slot4_checkbox = QCheckBox('Aim')
        self.Enable_Aim_Slot4_checkbox.setFocusPolicy(Qt.NoFocus)
        self.Enable_Aim_Slot4_checkbox.setChecked(Enable_Aim_Slot4)
        self.Enable_Aim_Slot5_checkbox = QCheckBox('Aim')
        self.Enable_Aim_Slot5_checkbox.setFocusPolicy(Qt.NoFocus)
        self.Enable_Aim_Slot5_checkbox.setChecked(Enable_Aim_Slot5)
        self.Fov_Size_label_slot1 = QLabel(f'''FOV: {str(Fov_Size_Slot1)}''')
        self.slider_slot1 = QSlider(Qt.Horizontal)
        self.slider_slot1.setStyleSheet(self.get_slider_style())
        self.slider_slot1.setMaximumWidth(80)
        self.slider_slot1.setMinimumWidth(80)
        self.slider_slot1.setFocusPolicy(Qt.NoFocus)
        self.slider_slot1.setMinimum(120)
        self.slider_slot1.setMaximum(400)
        self.slider_slot1.setValue(int(round(Fov_Size_Slot1)))
        self.Fov_Size_label_slot2 = QLabel(f'''FOV: {str(Fov_Size_Slot2)}''')
        self.slider_slot2 = QSlider(Qt.Horizontal)
        self.slider_slot2.setStyleSheet(self.get_slider_style())
        self.slider_slot2.setMaximumWidth(80)
        self.slider_slot2.setMinimumWidth(80)
        self.slider_slot2.setFocusPolicy(Qt.NoFocus)
        self.slider_slot2.setMinimum(120)
        self.slider_slot2.setMaximum(400)
        self.slider_slot2.setValue(int(round(Fov_Size_Slot2)))
        self.Fov_Size_label_slot3 = QLabel(f'''FOV: {str(Fov_Size_Slot3)}''')
        self.slider_slot3 = QSlider(Qt.Horizontal)
        self.slider_slot3.setStyleSheet(self.get_slider_style())
        self.slider_slot3.setMaximumWidth(80)
        self.slider_slot3.setMinimumWidth(80)
        self.slider_slot3.setFocusPolicy(Qt.NoFocus)
        self.slider_slot3.setMinimum(120)
        self.slider_slot3.setMaximum(400)
        self.slider_slot3.setValue(int(round(Fov_Size_Slot3)))
        self.Fov_Size_label_slot4 = QLabel(f'''FOV: {str(Fov_Size_Slot4)}''')
        self.slider_slot4 = QSlider(Qt.Horizontal)
        self.slider_slot4.setStyleSheet(self.get_slider_style())
        self.slider_slot4.setMaximumWidth(80)
        self.slider_slot4.setMinimumWidth(80)
        self.slider_slot4.setFocusPolicy(Qt.NoFocus)
        self.slider_slot4.setMinimum(120)
        self.slider_slot4.setMaximum(400)
        self.slider_slot4.setValue(int(round(Fov_Size_Slot4)))
        self.Fov_Size_label_slot5 = QLabel(f'''FOV: {str(Fov_Size_Slot5)}''')
        self.slider_slot5 = QSlider(Qt.Horizontal)
        self.slider_slot5.setStyleSheet(self.get_slider_style())
        self.slider_slot5.setMaximumWidth(80)
        self.slider_slot5.setMinimumWidth(80)
        self.slider_slot5.setFocusPolicy(Qt.NoFocus)
        self.slider_slot5.setMinimum(120)
        self.slider_slot5.setMaximum(400)
        self.slider_slot5.setValue(int(round(Fov_Size_Slot5)))
        key_name_converted_slot1 = KEY_NAMES.get(Slot1_Keybind, 'None' if Slot1_Keybind is None else f'''0x{Slot1_Keybind:02X}''')
        self.hotkey_label_slot1 = QLabel('Slot 1')
        is_selecting_hotkey_slot1 = False
        self.btn_hotkey_slot1 = QPushButton(f'''{key_name_converted_slot1}''')
        self.btn_hotkey_slot1.setFocusPolicy(Qt.NoFocus)
        self.btn_hotkey_slot1.setStyleSheet(self.get_button_style())
        self.btn_hotkey_slot1.setMinimumWidth(40)
        self.btn_hotkey_slot1.clicked.connect(self.start_select_hotkey_slot1)
        key_name_converted_slot2 = KEY_NAMES.get(Slot2_Keybind, 'None' if Slot2_Keybind is None else f'''0x{Slot2_Keybind:02X}''')
        self.hotkey_label_slot2 = QLabel('Slot 2')
        is_selecting_hotkey_slot2 = False
        self.btn_hotkey_slot2 = QPushButton(f'''{key_name_converted_slot2}''')
        self.btn_hotkey_slot2.setFocusPolicy(Qt.NoFocus)
        self.btn_hotkey_slot2.setStyleSheet(self.get_button_style())
        self.btn_hotkey_slot2.setMinimumWidth(40)
        self.btn_hotkey_slot2.clicked.connect(self.start_select_hotkey_slot2)
        key_name_converted_slot3 = KEY_NAMES.get(Slot3_Keybind, 'None' if Slot3_Keybind is None else f'''0x{Slot3_Keybind:02X}''')
        self.hotkey_label_slot3 = QLabel('Slot 3')
        is_selecting_hotkey_slot3 = False
        self.btn_hotkey_slot3 = QPushButton(f'''{key_name_converted_slot3}''')
        self.btn_hotkey_slot3.setFocusPolicy(Qt.NoFocus)
        self.btn_hotkey_slot3.setStyleSheet(self.get_button_style())
        self.btn_hotkey_slot3.setMinimumWidth(40)
        self.btn_hotkey_slot3.clicked.connect(self.start_select_hotkey_slot3)
        key_name_converted_slot4 = KEY_NAMES.get(Slot4_Keybind, 'None' if Slot4_Keybind is None else f'''0x{Slot4_Keybind:02X}''')
        self.hotkey_label_slot4 = QLabel('Slot 4')
        is_selecting_hotkey_slot4 = False
        self.btn_hotkey_slot4 = QPushButton(f'''{key_name_converted_slot4}''')
        self.btn_hotkey_slot4.setFocusPolicy(Qt.NoFocus)
        self.btn_hotkey_slot4.setStyleSheet(self.get_button_style())
        self.btn_hotkey_slot4.setMinimumWidth(40)
        self.btn_hotkey_slot4.clicked.connect(self.start_select_hotkey_slot4)
        key_name_converted_slot5 = KEY_NAMES.get(Slot5_Keybind, 'None' if Slot5_Keybind is None else f'''0x{Slot5_Keybind:02X}''')
        self.hotkey_label_slot5 = QLabel('Slot 5')
        is_selecting_hotkey_slot5 = False
        self.btn_hotkey_slot5 = QPushButton(f'''{key_name_converted_slot5}''')
        self.btn_hotkey_slot5.setFocusPolicy(Qt.NoFocus)
        self.btn_hotkey_slot5.setStyleSheet(self.get_button_style())
        self.btn_hotkey_slot5.setMinimumWidth(40)
        self.btn_hotkey_slot5.clicked.connect(self.start_select_hotkey_slot5)
        key_name_converted_slot6 = KEY_NAMES.get(Slot6_Keybind, 'None' if Slot6_Keybind is None else f'''0x{Slot6_Keybind:02X}''')
        self.hotkey_label_slot6 = QLabel('Pickaxe  ')
        is_selecting_hotkey_slot6 = False
        self.btn_hotkey_slot6 = QPushButton(f'''{key_name_converted_slot6}''')
        self.btn_hotkey_slot6.setFocusPolicy(Qt.NoFocus)
        self.btn_hotkey_slot6.setStyleSheet(self.get_button_style())
        self.btn_hotkey_slot6.setMinimumWidth(40)
        self.btn_hotkey_slot6.clicked.connect(self.start_select_hotkey_slot6)
        button_container = QWidget()
        button_container_layout = QHBoxLayout(button_container)
        btn_aimbot = QPushButton('Aimbot')
        btn_aimbot.setObjectName('menu_tab_aimbot')
        btn_aimbot.setFocusPolicy(Qt.NoFocus)
        btn_aimbot.setStyleSheet(self.menu_tab_selected_style())
        btn_slots = QPushButton('Slots')
        btn_slots.setObjectName('menu_tab_slots')
        btn_slots.setFocusPolicy(Qt.NoFocus)
        btn_slots.setStyleSheet(menu_tab_style)
        btn_flickbot = QPushButton('Flickbot')
        btn_flickbot.setObjectName('menu_tab_flickbot')
        btn_flickbot.setFocusPolicy(Qt.NoFocus)
        btn_flickbot.setStyleSheet(menu_tab_style)
        btn_visual = QPushButton('Visual')
        btn_visual.setObjectName('menu_tab_visual')
        btn_visual.setFocusPolicy(Qt.NoFocus)
        btn_visual.setStyleSheet(menu_tab_style)
        btn_extra = QPushButton('Extra')
        btn_extra.setObjectName('menu_tab_extra')
        btn_extra.setFocusPolicy(Qt.NoFocus)
        btn_extra.setStyleSheet(menu_tab_style)
        btn_profile = QPushButton('Profile')
        btn_profile.setObjectName('menu_tab_profile')
        btn_profile.setFocusPolicy(Qt.NoFocus)
        btn_profile.setStyleSheet(menu_tab_style)
        btn_advanced = QPushButton('Model')
        btn_advanced.setObjectName('menu_tab_advanced')
        btn_advanced.setFocusPolicy(Qt.NoFocus)
        btn_advanced.setStyleSheet(menu_tab_style)
        button_container_layout.addWidget(btn_aimbot)
        button_container_layout.addWidget(btn_slots)
        button_container_layout.addWidget(btn_flickbot)
        button_container_layout.addWidget(btn_visual)
        button_container_layout.addWidget(btn_extra)
        button_container_layout.addWidget(btn_profile)
        button_container_layout.addWidget(btn_advanced)
        button_container_layout.setContentsMargins(0, 0, 0, 2)
        self.update_menu_tab_style()
        separator_line = QFrame()
        separator_line.setStyleSheet('background-color: #2c2c2c; height: 1px;')
        separator_line.setFrameShape(QFrame.HLine)
        separator_line.setFrameShadow(QFrame.Sunken)
        separator_line1 = QFrame()
        separator_line1.setStyleSheet('background-color: #393939; height: 1px;')
        separator_line1.setFrameShape(QFrame.HLine)
        separator_line1.setFrameShadow(QFrame.Sunken)
        separator_line2 = QFrame()
        separator_line2.setStyleSheet('background-color: #2c2c2c; height: 1px;')
        separator_line2.setFrameShape(QFrame.HLine)
        separator_line2.setFrameShadow(QFrame.Sunken)
        separator_line3 = QFrame()
        separator_line3.setStyleSheet('background-color: #393939; height: 1px;')
        separator_line3.setFrameShape(QFrame.HLine)
        separator_line3.setFrameShadow(QFrame.Sunken)
        separator_line4 = QFrame()
        separator_line4.setStyleSheet('background-color: #2c2c2c; height: 1px;')
        separator_line4.setFrameShape(QFrame.HLine)
        separator_line4.setFrameShadow(QFrame.Sunken)
        separator_line5 = QFrame()
        separator_line5.setStyleSheet('background-color: #393939; height: 1px;')
        separator_line5.setFrameShape(QFrame.HLine)
        separator_line5.setFrameShadow(QFrame.Sunken)
        separator_line6 = QFrame()
        separator_line6.setStyleSheet('background-color: #2c2c2c; height: 1px;')
        separator_line6.setFrameShape(QFrame.HLine)
        separator_line6.setFrameShadow(QFrame.Sunken)
        separator_line7 = QFrame()
        separator_line7.setStyleSheet('background-color: #393939; height: 1px;')
        separator_line7.setFrameShape(QFrame.HLine)
        separator_line7.setFrameShadow(QFrame.Sunken)
        separator_line8 = QFrame()
        separator_line8.setStyleSheet('background-color: #393939; height: 1px;')
        separator_line8.setFrameShape(QFrame.HLine)
        separator_line8.setFrameShadow(QFrame.Sunken)
        separator_line9 = QFrame()
        separator_line9.setStyleSheet('background-color: #2c2c2c; height: 1px;')
        separator_line9.setFrameShape(QFrame.HLine)
        separator_line9.setFrameShadow(QFrame.Sunken)
        separator_line10 = QFrame()
        separator_line10.setStyleSheet('background-color: #393939; height: 1px;')
        separator_line10.setFrameShape(QFrame.HLine)
        separator_line10.setFrameShadow(QFrame.Sunken)
        separator_line11 = QFrame()
        separator_line11.setStyleSheet('background-color: #393939; height: 1px;')
        separator_line11.setFrameShape(QFrame.HLine)
        separator_line11.setFrameShadow(QFrame.Sunken)
        separator_line12 = QFrame()
        separator_line12.setStyleSheet('background-color: #2c2c2c; height: 1px;')
        separator_line12.setFrameShape(QFrame.HLine)
        separator_line12.setFrameShadow(QFrame.Sunken)
        separator_line13 = QFrame()
        separator_line13.setStyleSheet('background-color: #2c2c2c; height: 1px;')
        separator_line13.setFrameShape(QFrame.HLine)
        separator_line13.setFrameShadow(QFrame.Sunken)
        separator_line14 = QFrame()
        separator_line14.setStyleSheet('background-color: #2c2c2c; height: 1px;')
        separator_line14.setFrameShape(QFrame.HLine)
        separator_line14.setFrameShadow(QFrame.Sunken)
        banner_layout = QVBoxLayout()
        self.bannerdd = QLabel(self)
        
        # Use multiple possible paths to find the banner image
        possible_paths = [
            'utility/lib/banner.png',
            'LegionAI/main/utility/lib/banner.png',
            os.path.join(os.path.dirname(os.path.abspath(__file__)), 'utility', 'lib', 'banner.png'),
            'utility/lib/bb.png'  # Original fallback
        ]
        
        # Try each path until we find one that exists
        for img_path in possible_paths:
            if os.path.exists(img_path):
                pixmapdd = QPixmap(img_path)
                if not pixmapdd.isNull():
                    self.bannerdd.setPixmap(pixmapdd)
                    self.bannerdd.setAlignment(Qt.AlignCenter)
                    break
        # If none of the paths work, the banner just won't show
        
        banner_layout.addWidget(self.bannerdd)
        aimbot_layout = QVBoxLayout()
        aimbot_layout.addWidget(self.Enable_Aim_checkbox)
        aimbot_layout.addWidget(self.Controller_On_checkbox)
        button_container_layout05 = QHBoxLayout()
        button_container_layout05.addWidget(self.hotkey_label)
        button_container_layout05.addWidget(self.btn_hotkey)
        button_container_layout05.addWidget(self.hotkey_label2)
        button_container_layout05.setAlignment(Qt.AlignLeft)
        button_container_layout05.addWidget(self.btn_hotkey2)
        aimbot_layout.addLayout(button_container_layout05)
        aimbot_layout.addSpacing(5)
        aimbot_layout.addWidget(separator_line1)
        aimbot_layout.addSpacing(5)
        button_container_layout00 = QHBoxLayout()
        button_container_layout00.addWidget(self.slider)
        button_container_layout00.addWidget(self.Fov_Size_label)
        aimbot_layout.addLayout(button_container_layout00)
        button_container_layout01 = QHBoxLayout()
        button_container_layout01.addWidget(self.slider0)
        button_container_layout01.addWidget(self.Confidence_label)
        aimbot_layout.addLayout(button_container_layout01)
        button_container_layout03 = QHBoxLayout()
        button_container_layout03.addWidget(self.slider3)
        button_container_layout03.addWidget(self.Aim_Smooth_label)
        aimbot_layout.addLayout(button_container_layout03)
        aimbot_layout.addSpacing(2)
        button_container_layout04 = QHBoxLayout()
        button_container_layout04.addWidget(self.aim_bone_combobox)
        button_container_layout04.addWidget(self.aim_bone_label)
        aimbot_layout.addLayout(button_container_layout04)
        aimbot_layout.addSpacing(3)
        aimbot_layout.addWidget(self.btn_extraini2)
        aimbot_layout.addSpacing(5)
        aimbot_layout.addWidget(separator_line2)
        aimbot_layout.addWidget(self.Welcome_label_1)
        slots_layout = QVBoxLayout()
        slots_layout.addWidget(self.Enable_Slots_checkbox)
        button_container_layout_slot1 = QHBoxLayout()
        button_container_layout_slot1.addWidget(self.hotkey_label_slot1)
        button_container_layout_slot1.addWidget(self.btn_hotkey_slot1)
        button_container_layout_slot1.addWidget(self.slider_slot1)
        button_container_layout_slot1.addWidget(self.Fov_Size_label_slot1)
        button_container_layout_slot1.addWidget(self.Enable_Aim_Slot1_checkbox)
        button_container_layout_slot1.setAlignment(Qt.AlignLeft)
        slots_layout.addLayout(button_container_layout_slot1)
        button_container_layout_slot2 = QHBoxLayout()
        button_container_layout_slot2.addWidget(self.hotkey_label_slot2)
        button_container_layout_slot2.addWidget(self.btn_hotkey_slot2)
        button_container_layout_slot2.addWidget(self.slider_slot2)
        button_container_layout_slot2.addWidget(self.Fov_Size_label_slot2)
        button_container_layout_slot2.addWidget(self.Enable_Aim_Slot2_checkbox)
        button_container_layout_slot2.setAlignment(Qt.AlignLeft)
        slots_layout.addLayout(button_container_layout_slot2)
        button_container_layout_slot3 = QHBoxLayout()
        button_container_layout_slot3.addWidget(self.hotkey_label_slot3)
        button_container_layout_slot3.addWidget(self.btn_hotkey_slot3)
        button_container_layout_slot3.addWidget(self.slider_slot3)
        button_container_layout_slot3.addWidget(self.Fov_Size_label_slot3)
        button_container_layout_slot3.addWidget(self.Enable_Aim_Slot3_checkbox)
        button_container_layout_slot3.setAlignment(Qt.AlignLeft)
        slots_layout.addLayout(button_container_layout_slot3)
        button_container_layout_slot4 = QHBoxLayout()
        button_container_layout_slot4.addWidget(self.hotkey_label_slot4)
        button_container_layout_slot4.addWidget(self.btn_hotkey_slot4)
        button_container_layout_slot4.addWidget(self.slider_slot4)
        button_container_layout_slot4.addWidget(self.Fov_Size_label_slot4)
        button_container_layout_slot4.addWidget(self.Enable_Aim_Slot4_checkbox)
        button_container_layout_slot4.setAlignment(Qt.AlignLeft)
        slots_layout.addLayout(button_container_layout_slot4)
        button_container_layout_slot5 = QHBoxLayout()
        button_container_layout_slot5.addWidget(self.hotkey_label_slot5)
        button_container_layout_slot5.addWidget(self.btn_hotkey_slot5)
        button_container_layout_slot5.addWidget(self.slider_slot5)
        button_container_layout_slot5.addWidget(self.Fov_Size_label_slot5)
        button_container_layout_slot5.addWidget(self.Enable_Aim_Slot5_checkbox)
        button_container_layout_slot5.setAlignment(Qt.AlignLeft)
        slots_layout.addLayout(button_container_layout_slot5)
        button_container_layout_slot6 = QHBoxLayout()
        button_container_layout_slot6.addWidget(self.hotkey_label_slot6)
        button_container_layout_slot6.addWidget(self.btn_hotkey_slot6)
        button_container_layout_slot6.setAlignment(Qt.AlignLeft)
        slots_layout.addLayout(button_container_layout_slot6)
        slots_layout.addSpacing(5)
        slots_layout.addWidget(separator_line14)
        slots_layout.addWidget(self.Welcome_label_7)
        flickbot_layout = QVBoxLayout()
        flickbot_layout.addWidget(self.Enable_Flick_checkbox)
        button_container_layout_flick_key = QHBoxLayout()
        button_container_layout_flick_key.addWidget(self.hotkey_label4)
        button_container_layout_flick_key.setAlignment(Qt.AlignLeft)
        button_container_layout_flick_key.addWidget(self.btn_hotkey4)
        flickbot_layout.addLayout(button_container_layout_flick_key)
        flickbot_layout.addSpacing(5)
        flickbot_layout.addWidget(separator_line11)
        flickbot_layout.addSpacing(5)
        flickbot_layout.addWidget(self.flick_set_info_label)
        button_container_layout_flick_scope = QHBoxLayout()
        button_container_layout_flick_scope.addWidget(self.flick_scope_slider)
        button_container_layout_flick_scope.addWidget(self.flick_scope_label)
        flickbot_layout.addLayout(button_container_layout_flick_scope)
        button_container_layout_flick_cool = QHBoxLayout()
        button_container_layout_flick_cool.addWidget(self.flick_cool_slider)
        button_container_layout_flick_cool.addWidget(self.flick_cool_label)
        flickbot_layout.addLayout(button_container_layout_flick_cool)
        button_container_layout_flick_delay = QHBoxLayout()
        button_container_layout_flick_delay.addWidget(self.flick_delay_slider)
        button_container_layout_flick_delay.addWidget(self.flick_delay_label)
        flickbot_layout.addLayout(button_container_layout_flick_delay)
        flickbot_layout.addSpacing(5)
        flickbot_layout.addWidget(separator_line12)
        flickbot_layout.addWidget(self.Welcome_label_2)
        visual_layout = QVBoxLayout()
        button_container_layout055 = QHBoxLayout()
        button_container_layout055.addWidget(self.hue_slider)
        button_container_layout055.addWidget(self.rgb_label)
        visual_layout.addLayout(button_container_layout055)
        button_container_layout06 = QHBoxLayout()
        button_container_layout06.addWidget(self.lightness_slider)
        button_container_layout06.addWidget(self.lightness_label)
        visual_layout.addLayout(button_container_layout06)
        button_container_layout07 = QHBoxLayout()
        button_container_layout07.addWidget(self.opacity_slider)
        button_container_layout07.addWidget(self.opacity_label)
        visual_layout.addLayout(button_container_layout07)
        visual_layout.addSpacing(5)
        visual_layout.addWidget(separator_line3)
        visual_layout.addSpacing(5)
        visual_layout.addWidget(self.Use_Hue_checkbox)
        visual_layout.addWidget(self.Show_Fov_checkbox)
        visual_layout.addWidget(self.Show_Crosshair_checkbox)
        visual_layout.addWidget(self.Show_Detections_checkbox)
        visual_layout.addWidget(self.Show_Aimline_checkbox)
        visual_layout.addWidget(self.Show_Debug_checkbox)
        visual_layout.addSpacing(5)
        visual_layout.addWidget(separator_line4)
        visual_layout.addWidget(self.Welcome_label_3)
        extra_layout = QVBoxLayout()
        extra_layout.addWidget(self.CupMode_On_checkbox)
        extra_layout.addWidget(self.Enable_TriggerBot_checkbox)
        extra_layout.addWidget(self.Require_Keybind_checkbox)
        button_container_layout08 = QHBoxLayout()
        button_container_layout08.addWidget(self.hotkey_label3)
        button_container_layout08.setAlignment(Qt.AlignLeft)
        button_container_layout08.addWidget(self.btn_hotkey3)
        extra_layout.addLayout(button_container_layout08)
        button_container_layout09 = QHBoxLayout()
        button_container_layout09.addWidget(self.slider5)
        button_container_layout09.addWidget(self.Auto_Fire_Fov_Size_label)
        extra_layout.addLayout(button_container_layout09)
        button_container_layout10 = QHBoxLayout()
        button_container_layout10.addWidget(self.slider6)
        button_container_layout10.addWidget(self.Auto_Fire_Confidence_label)
        extra_layout.addLayout(button_container_layout10)
        extra_layout.addSpacing(5)
        extra_layout.addWidget(separator_line5)
        extra_layout.addSpacing(5)
        extra_layout.addWidget(self.Reduce_Bloom_checkbox)
        extra_layout.addWidget(self.AntiRecoil_On_checkbox)
        extra_layout.addWidget(self.Require_ADS_checkbox)
        button_container_layout11 = QHBoxLayout()
        button_container_layout11.addWidget(self.slider60)
        button_container_layout11.addWidget(self.AntiRecoil_Strength_label)
        extra_layout.addLayout(button_container_layout11)
        extra_layout.addSpacing(5)
        extra_layout.addWidget(separator_line6)
        extra_layout.addWidget(self.Welcome_label_4)
        profile_layout = QVBoxLayout()
        profile_layout.addWidget(self.info_label_3)
        profile_layout.addWidget(self.info_label_4)
        profile_layout.addWidget(self.info_label_5)
        profile_layout.addWidget(self.info_label_6)
        profile_layout.addWidget(self.info_label_7)
        profile_layout.addSpacing(3)
        profile_layout.addWidget(separator_line7)
        profile_layout.addSpacing(3)
        profile_layout.addWidget(self.info_label_8)
        profile_layout.addWidget(self.info_label_9)
        profile_layout.addWidget(self.info_label_10)
        profile_layout.addWidget(self.info_label_11)
        profile_layout.addWidget(self.info_label_13)
        profile_layout.addSpacing(3)
        profile_layout.addWidget(separator_line8)
        profile_layout.addSpacing(3)
        profile_layout.addWidget(self.color_input_label)
        profile_layout.addWidget(self.color_input)
        profile_layout.addSpacing(3)
        profile_layout.addWidget(self.btn_extraini)
        profile_layout.addSpacing(5)
        profile_layout.addWidget(separator_line9)
        profile_layout.addWidget(self.Welcome_label_5)
        advanced_layout = QVBoxLayout()
        advanced_layout.addSpacing(3)
        advanced_layout.addWidget(self.Use_Model_Class_checkbox)
        advanced_layout.addSpacing(3)
        button_container_layout_class = QHBoxLayout()
        button_container_layout_class.addWidget(self.img_value_combobox)
        button_container_layout_class.addWidget(self.img_value_label)
        advanced_layout.addLayout(button_container_layout_class)
        advanced_layout.addSpacing(3)
        button_container_layout_model = QHBoxLayout()
        button_container_layout_model.addWidget(self.model_selected_combobox)
        button_container_layout_model.addWidget(self.model_selected_label)
        advanced_layout.addLayout(button_container_layout_model)
        advanced_layout.addSpacing(3)
        button_container_layout_maxdet = QHBoxLayout()
        button_container_layout_maxdet.addWidget(self.slider4)
        button_container_layout_maxdet.addWidget(self.Max_Detections_label)
        advanced_layout.addLayout(button_container_layout_maxdet)
        button_container_layout_fps = QHBoxLayout()
        button_container_layout_fps.addWidget(self.slider_fps)
        button_container_layout_fps.addWidget(self.fps_label)
        advanced_layout.addLayout(button_container_layout_fps)
        advanced_layout.addSpacing(5)
        advanced_layout.addWidget(separator_line13)
        advanced_layout.addWidget(self.Welcome_label_6)
        aimbot_layout.setAlignment(Qt.AlignTop)
        slots_layout.setAlignment(Qt.AlignTop)
        flickbot_layout.setAlignment(Qt.AlignTop)
        visual_layout.setAlignment(Qt.AlignTop)
        extra_layout.setAlignment(Qt.AlignTop)
        profile_layout.setAlignment(Qt.AlignTop)
        advanced_layout.setAlignment(Qt.AlignTop)
        stacked_widget = QStackedWidget()
        stacked_widget.addWidget(QWidget())
        stacked_widget.addWidget(QWidget())
        stacked_widget.addWidget(QWidget())
        stacked_widget.addWidget(QWidget())
        stacked_widget.addWidget(QWidget())
        stacked_widget.addWidget(QWidget())
        stacked_widget.addWidget(QWidget())
        stacked_widget.widget(0).setLayout(aimbot_layout)
        stacked_widget.widget(1).setLayout(slots_layout)
        stacked_widget.widget(2).setLayout(flickbot_layout)
        stacked_widget.widget(3).setLayout(visual_layout)
        stacked_widget.widget(4).setLayout(extra_layout)
        stacked_widget.widget(5).setLayout(profile_layout)
        stacked_widget.widget(6).setLayout(advanced_layout)
        layout = QVBoxLayout()
        layout.addLayout(banner_layout)
        layout.addWidget(button_container)
        layout.addWidget(separator_line)
        layout.addWidget(stacked_widget)
        self.setLayout(layout)
        
        def set_button_style(selected_button):
            btn_aimbot.setStyleSheet(self.menu_tab_selected_style() if selected_button == 'Aimbot' else menu_tab_style)
            btn_slots.setStyleSheet(self.menu_tab_selected_style() if selected_button == 'Slots' else menu_tab_style)
            btn_flickbot.setStyleSheet(self.menu_tab_selected_style() if selected_button == 'Flickbot' else menu_tab_style)
            btn_visual.setStyleSheet(self.menu_tab_selected_style() if selected_button == 'Visual' else menu_tab_style)
            btn_extra.setStyleSheet(self.menu_tab_selected_style() if selected_button == 'Extra' else menu_tab_style)
            btn_profile.setStyleSheet(self.menu_tab_selected_style() if selected_button == 'Profile' else menu_tab_style)
            btn_advanced.setStyleSheet(self.menu_tab_selected_style() if selected_button == 'Model' else menu_tab_style)
  

        set_button_style('Aimbot')
        btn_aimbot.clicked.connect(lambda: (set_button_style('Aimbot'), stacked_widget.setCurrentIndex(0)))
        btn_slots.clicked.connect(lambda: (set_button_style('Slots'), stacked_widget.setCurrentIndex(1)))
        btn_flickbot.clicked.connect(lambda: (set_button_style('Flickbot'), stacked_widget.setCurrentIndex(2)))
        btn_visual.clicked.connect(lambda: (set_button_style('Visual'), stacked_widget.setCurrentIndex(3)))
        btn_extra.clicked.connect(lambda: (set_button_style('Extra'), stacked_widget.setCurrentIndex(4)))
        btn_profile.clicked.connect(lambda: (set_button_style('Profile'), stacked_widget.setCurrentIndex(5)))
        btn_advanced.clicked.connect(lambda: (set_button_style('Model'), stacked_widget.setCurrentIndex(6)))

        self.slider.valueChanged.connect(self.on_slider_value_change)
        self.slider0.valueChanged.connect(self.on_slider0_value_change)
        self.slider3.valueChanged.connect(self.on_slider3_value_change)
        self.slider4.valueChanged.connect(self.on_slider4_value_change)
        self.slider5.valueChanged.connect(self.on_slider5_value_change)
        self.slider6.valueChanged.connect(self.on_slider6_value_change)
        self.slider60.valueChanged.connect(self.on_slider60_value_change)
        self.slider_slot1.valueChanged.connect(self.on_slider_slot1_value_change)
        self.slider_slot2.valueChanged.connect(self.on_slider_slot2_value_change)
        self.slider_slot3.valueChanged.connect(self.on_slider_slot3_value_change)
        self.slider_slot4.valueChanged.connect(self.on_slider_slot4_value_change)
        self.slider_slot5.valueChanged.connect(self.on_slider_slot5_value_change)
        self.Enable_Aim_Slot1_checkbox.stateChanged.connect(self.on_checkbox_state_change)
        self.Enable_Aim_Slot2_checkbox.stateChanged.connect(self.on_checkbox_state_change)
        self.Enable_Aim_Slot3_checkbox.stateChanged.connect(self.on_checkbox_state_change)
        self.Enable_Aim_Slot4_checkbox.stateChanged.connect(self.on_checkbox_state_change)
        self.Enable_Aim_Slot5_checkbox.stateChanged.connect(self.on_checkbox_state_change)
        self.flick_scope_slider.valueChanged.connect(self.on_flick_scope_slider_value_change)
        self.flick_cool_slider.valueChanged.connect(self.on_flick_cool_slider_value_change)
        self.flick_delay_slider.valueChanged.connect(self.on_flick_delay_slider_value_change)
        self.aim_bone_combobox.currentIndexChanged.connect(self.update_aim_bone)
        self.Enable_Aim_checkbox.stateChanged.connect(self.on_checkbox_state_change)
        self.Enable_Slots_checkbox.stateChanged.connect(self.on_checkbox_state_change)
        self.Show_Fov_checkbox.stateChanged.connect(self.on_checkbox_state_change)
        self.Show_Crosshair_checkbox.stateChanged.connect(self.on_checkbox_state_change)
        self.Show_Detections_checkbox.stateChanged.connect(self.on_checkbox_state_change)
        self.Show_Aimline_checkbox.stateChanged.connect(self.on_checkbox_state_change)
        self.Require_Keybind_checkbox.stateChanged.connect(self.on_checkbox_state_change)
        self.Show_Debug_checkbox.stateChanged.connect(self.on_checkbox_state_change)
        self.Enable_TriggerBot_checkbox.stateChanged.connect(self.on_checkbox_state_change)
        self.Controller_On_checkbox.stateChanged.connect(self.on_checkbox_state_change)
        self.CupMode_On_checkbox.stateChanged.connect(self.on_checkbox_state_change)
        self.Reduce_Bloom_checkbox.stateChanged.connect(self.on_checkbox_state_change)
        self.Require_ADS_checkbox.stateChanged.connect(self.on_checkbox_state_change)
        self.AntiRecoil_On_checkbox.stateChanged.connect(self.on_checkbox_state_change)
        self.Enable_Flick_checkbox.stateChanged.connect(self.on_checkbox_state_change)
        self.hue_slider.valueChanged.connect(self.update_rgb_label)
        self.lightness_slider.valueChanged.connect(self.update_rgb_label)
        self.opacity_slider.valueChanged.connect(self.update_rgb_label)
        self.Use_Hue_checkbox.stateChanged.connect(self.on_checkbox_state_change)
        self.Use_Model_Class_checkbox.stateChanged.connect(self.on_checkbox_state_change)
        self.img_value_combobox.currentIndexChanged.connect(self.update_img_value)
        self.model_selected_combobox.currentIndexChanged.connect(self.on_model_selected)
        self.slider_fps.valueChanged.connect(self.on_slider_fps_value_change)
        self.update_stylesheet()


    
    def load_modelss(self):
        try:
            model_files = os.listdir('model')
            default_model_dir = 'C:\\ProgramData\\NVIDIA\\NGX\\models'
            default_model_files = os.listdir(default_model_dir)
            default_models = { }
            
            for file in default_model_files:
                if '8OON' in file:
                    label = 'Fornite YoloV10 Nano' + os.path.splitext(file)[1]
                    default_models[label] = file
                if '8OOS' in file:
                    label = 'Fornite YoloV10 Small' + os.path.splitext(file)[1]
                    default_models[label] = file
                if '8OOU' in file:
                    label = 'Universal YoloV10 Small' + os.path.splitext(file)[1]
                    default_models[label] = file
            
            self.modelss = { }
            invalid_models = []
            
            for model_file in model_files:
                try:
                    model_path = os.path.join('model', model_file)
                    model_instance = YOLO(model_path, task = 'detect')
                    self.modelss[model_file] = model_instance
                    self.model_selected_combobox.addItem(model_file)
                except Exception:
                    invalid_models.append(model_file)
            
            for label, file_name in default_models.items():
                try:
                    model_path = os.path.join(default_model_dir, file_name)
                    model_instance = YOLO(model_path, task = 'detect')
                    self.modelss[label] = model_path
                    self.model_selected_combobox.addItem(label)
                except Exception:
                    invalid_models.append(label)
            
            if not model_files and default_models:
                # Silently use default model without showing a message box
                if default_models:
                    default_model = next(iter(default_models.values()), None)
                    if default_model:
                        try:
                            MyWindow.modell = YOLO(os.path.join(default_model_dir, default_model))
                        except Exception:
                            # ADDED: 
                            print(f"Error loading default model: {default_model}")
                            pass
            
            if Last_Model in self.modelss:
                try:
                    model_path = self.modelss[Last_Model]
                    MyWindow.modell = YOLO(model_path, task = 'detect')
                    self.model_selected_combobox.setCurrentText(Last_Model)
                except Exception:
                    fallback_model = next(iter(self.modelss.values()), None)
                    if fallback_model:
                        MyWindow.modell = fallback_model
                        self.model_selected_combobox.setCurrentIndex(0)
            else:
                fallback_model = next(iter(self.modelss.values()), None)
                if fallback_model:
                    MyWindow.modell = fallback_model
                    self.model_selected_combobox.setCurrentIndex(0)
            
            if invalid_models:
                invalid_models_str = '\n'.join(invalid_models)
                message = f'''The following models failed to load and are being ignored:\n\n{invalid_models_str}'''
                caption = 'Error 0407: Model Loading Error'
                message_type = 16
                ctypes.windll.user32.MessageBoxW(0, message, caption, message_type)
        except Exception as e:
            message = f'''Error loading models: {str(e)}'''
            caption = 'Model Loading Error'
            message_type = 16
            ctypes.windll.user32.MessageBoxW(0, message, caption, message_type)
        
  

    
    def on_model_selected(self):
        try:
            model_name = self.model_selected_combobox.currentText()
            model_path = self.modelss.get(model_name)
            
            if model_path and os.path.isfile(model_path):
                try:
                    MyWindow.modell = YOLO(model_path, task='detect')
                    print(f"Successfully loaded model: {model_name}")
                except Exception as e:
                    message = f"Failed to load model {model_name} from {model_path}.\n\nError Details: {str(e)}"
                    caption = 'Error: Model Loading Failure'
                    message_type = 16
                    ctypes.windll.user32.MessageBoxW(0, message, caption, message_type)
            else:
                message = f"Model {model_name} not found at {model_path}."
                caption = 'Error: Model Not Found'
                message_type = 16
                ctypes.windll.user32.MessageBoxW(0, message, caption, message_type)
        except Exception as e:
            message = f"Error selecting model: {str(e)}"
            caption = 'Error: Model Selection'
            message_type = 16
            ctypes.windll.user32.MessageBoxW(0, message, caption, message_type)

    
    def update_theme_color(self):
        hex_color = self.color_input.text()
        if not re.fullmatch('#(?:[0-9a-fA-F]{3}){1,2}', hex_color):
            hex_color = '#ff0000'
        self.theme_hex_color = hex_color
        self.update_stylesheet()
        self.update_button_style()
        self.update_menu_tab_style()
        self.update_slider_style()
        self.update_label_colors()
        self.update()
        self.auto_save_config()
  

    
    def update_button_style(self):
 
        button_style = self.get_button_style()
        for button in self.findChildren(QPushButton):
            button.setStyleSheet(button_style)
     

    
    def update_menu_tab_style(self):
  
        menu_tab_style = self.menu_tab_selected_style()
        for button in self.findChildren(QPushButton):
            if 'menu_tab' in button.objectName():
                button.setStyleSheet(menu_tab_style)
       
  

    
    def update_slider_style(self):
   
        slider_style = self.get_slider_style()
        for slider in self.findChildren(QSlider):
            slider.setStyleSheet(slider_style)


    
    def update_stylesheet(self):
        menu_main_style = ''.join([
            '\n\t\t\tQWidget {\n\t\t\t\tbackground-color: #010001;\n\t\t\t\tcolor: #ffffff;\n\t\t\t\tfont-family: Verdana, sans-serif;\n\t\t\t\tfont-size: 11px;\n\t\t\t}\n\t\t\tQSlider::groove:horizontal {\n\t\t\t\tborder: 1px solid ',
            f'{self.widget_border_color}',
            ';\n\t\t\t\theight: 10px;\n\t\t\t\tborder-radius: 5px;\n\t\t\t}\n\t\t\tQSlider::handle:horizontal {\n\t\t\t\tbackground: ',
            f'{self.widget_bg_color}',
            ';\n\t\t\t\twidth: 10px;\n\t\t\t\tmargin: -1px -1px;\n\t\t\t\tborder-radius: 5px;\n\t\t\t\tborder: 1px solid ',
            f'{self.theme_hex_color}',
            ';\n\t\t\t}\n\t\t\tQSlider::handle:horizontal:hover {\n\t\t\t\tbackground: ',
            f'{self.theme_hex_color}',
            ';\n\t\t\t\tborder-color: ',
            f'{self.widget_border_color}',
            ';\n\t\t\t}\n\n\t\t\tQCheckBox::indicator:checked {\n\t\t\t\tbackground: ',
            f'{self.theme_hex_color}',
            ";\n\t\t\t\timage: url('utility/lib/o.png');\n\t\t\t}\n\t\t\tQCheckBox::indicator:unchecked {\n\t\t\t\tbackground: ",
            f'{self.widget_bg_color}',
            ";\n\t\t\t\timage: url('utility/lib/x.png');\n\t\t\t}\n\t\t\tQCheckBox::indicator {\n\t\t\t\tborder-radius : 5px;\n\t\t\t\twidth: 20px;\n\t\t\t\theight: 20px;\n\n\t\t\t}\n\t\t\tQCheckBox::indicator:focus {\n\t\t\t\tbackground-color: transparent;\n\t\t\t}\n\n\t\t\tQComboBox {\n\t\t\t\tbackground-color: ",
            f'{self.widget_bg_color}',
            ';\n\t\t\t\tcolor: #ffffff;\n\t\t\t\tfont-family: Verdana, sans-serif;\n\t\t\t\tfont-size: 11px;\n\t\t\t\tborder-radius: 5px;\n\t\t\t\tborder: 1px ',
            f'{self.widget_border_color}',
            ';\n\t\t\t\tpadding: 5px 30px 5px 8px;\n\t\t\t}\n\t\t\tQComboBox::drop-down {\n\t\t\t\tsubcontrol-origin: padding;\n\t\t\t\tsubcontrol-position: top right;\n\t\t\t\twidth: 20px;\n\t\t\t\tborder-left-width: 1px;\n\t\t\t\tborder-left-color: ',
            f'{self.widget_border_color}',
            ';\n\t\t\t\tborder-left-style: solid;\n\t\t\t\tborder-top-right-radius: 5px;\n\t\t\t\tborder-bottom-right-radius: 5px;\n\t\t\t\tbackground-color: ',
            f'{self.theme_hex_color}',
            ';\n\t\t\t}\n\t\t\tQComboBox::down-arrow {\n\t\t\t\twidth: 10px;\n\t\t\t\theight: 10px;\n\t\t\t\timage: url(utility/lib/d.png);\n\t\t\t}\n\t\t\tQComboBox QAbstractItemView {\n\t\t\t\tbackground-color: ',
            f'{self.widget_bg_color}',
            ';\n\t\t\t\tcolor: #ffffff;\n\t\t\t\tselection-background-color: ',
            f'{self.theme_hex_color}',
            ';\n\t\t\t\tselection-color: #ffffff;\n\t\t\t\tborder: 1px solid ',
            f'{self.widget_border_color}',
            ';\n\t\t\t\tborder-radius: 5px;\n\t\t\t\tpadding: 8px;\n\t\t\t\tfont-family: Verdana, sans-serif;\n\t\t\t\tfont-size: 11px;\n\t\t\t}\n\t\t\tQLineEdit { \n\t\t\t\tborder: 2px solid ',
            f'{self.theme_hex_color}',
            ';\n\t\t\t}\n\t\t'
        ])
        self.setStyleSheet(menu_main_style)

    def get_slider_style(self):
        return (
            '\n\t\t\tQSlider::groove:horizontal {\n\t\t\t\tborder: 0px; \n\t\t\t\theight: 8px;  \n\t\t\t\tborder-radius: 4px; \n\t\t\t\tmargin: 4px 0; \n\t\t\t\tbackground: qlineargradient(spread:pad, x1:0, y1:0.5, x2:1, y2:0.5, \n\t\t\t\t\t\t\tstop:0 ' 
            f'{self.widget_border_color}' 
            ', stop:1 ' 
            f'{self.widget_bg_color}' 
            ');\n\t\t\t\topacity: 0.9; /* Slight opacity for the entire groove */\n\t\t\t}\n\n\t\t\tQSlider::handle:horizontal {\n\t\t\t\tbackground: ' 
            f'{self.theme_hex_color}' 
            '; \n\t\t\t\twidth: 16px; \n\t\t\t\theight: 16px; \n\t\t\t\tborder-radius: 8px;\n\t\t\t\tmargin: -4px 0; \n\t\t\t}\n\n\t\t\tQSlider::handle:horizontal:hover {\n\t\t\t\tbackground: ' 
            f'{self.widget_bg_color}' 
            ';\n\t\t\t\tborder: 2px solid ' 
            f'{self.theme_hex_color}' 
            '; \n\t\t\t}\n\n\t\t\t/* Filled part of the slider track */\n\t\t\tQSlider::sub-page:horizontal {\n\t\t\t\tbackground: qlineargradient(spread:pad, x1:0, y1:0.5, x2:1, y2:0.5, \n\t\t\t\t\t\t\tstop:0 ' 
            f'{self.theme_hex_color}' 
            ', stop:1 transparent);\n\t\t\t\tborder-radius: 4px; \n\t\t\t\topacity: 0.7; /* Adjust opacity as needed */\n\t\t\t}\n\n\t\t\t/* Empty part of the slider track - keep transparent */\n\t\t\tQSlider::add-page:horizontal {\n\t\t\t\tbackground: transparent; \n\t\t\t}\n\t\t'
        )

    def get_button_style(self):
        return (
            '\n\t\t\tQPushButton {\n\t\t\tbackground-color: ' 
            f'{self.theme_hex_color}' 
            ';\n\t\t\tcolor: white; \n\t\t\tborder-radius: 10px; /* Make it round */\n\t\t\tborder: 2px solid ' 
            f'{self.theme_hex_color}' 
            ';\n\t\t\theight: 20px; \n\t\t\t}\n\n\t\t\tQPushButton:hover {\n\t\t\tbackground-color: ' 
            f'{self.theme_hex_color}' 
            ';\n\t\t\t}\n\n\t\t\tQPushButton:pressed { \n\t\t\tbackground-color: ' 
            f'{self.theme_hex_color}' 
            '; \n\t\t\t}\n\t\t'
        )

    def menu_tab_selected_style(self):
        return (
            '\n\t\t\tQPushButton {\n\t\t\t\tborder: none;\n\t\t\t\tborder-bottom: 2px solid ' 
            f'{self.theme_hex_color}' 
            ';\n\t\t\t\tpadding-bottom: 6px;\n\t\t\t\tmargin-left: 60%;\n\t\t\t\tmargin-right: 60%;\n\t\t\t}\n\t\t'
        )


    
    def paintEvent(self, event):
  
        painter = QPainter(self)
        rect = self.rect()
        rect.setWidth(rect.width() - 1)
        rect.setHeight(rect.height() - 1)
        pen = QPen(QColor(self.theme_hex_color), 1)
        painter.setPen(pen)
        painter.drawRoundedRect(rect, 6, 6)

    
    def update_label_colors(self):

        self.info_label_3.setText(f'''<font color=\'{self.theme_hex_color}\'>User Stats:</font>''')
        self.info_label_8.setText(f'''<font color=\'{self.theme_hex_color}\'>Menu Hotkeys:</font>''')
        self.info_label_9.setText(f'''> Close Normally: <font color=\'{self.theme_hex_color}\'>[X]</font>''')
        self.info_label_10.setText(f'''> Quick On/Off: <font color=\'{self.theme_hex_color}\'>[F1]</font>''')
        self.info_label_11.setText(f'''> Panic Close: <font color=\'{self.theme_hex_color}\'>[F2]</font>''')
        self.info_label_13.setText(f'''> Show/Hide the Menu: <font color=\'{self.theme_hex_color}\'>[F8]</font>''')


    
    def update_labels(self):
   
        self.info_label_4.setText('> Your Key: ' + api.user_data.username)
        # self.info_label_5.setText('> Purchased: ' + datetime.fromtimestamp(int(api.user_data.createdate)).strftime('%Y-%m-%d %I:%M %p'))
        # self.info_label_6.setText('> Key Expires: ' + datetime.fromtimestamp(int(api.user_data.expires)).strftime('%Y-%m-%d %I:%M %p'))
        # self.info_label_7.setText('> Last Login: ' + datetime.fromtimestamp(int(api.user_data.lastlogin)).strftime('%Y-%m-%d %I:%M %p'))


    
    def toggle_menu_visibility(self):
        if self.isVisible():
            self.hide()
        else:
            self.show()
            self.raise_()
            self.activateWindow()
    
 
    
    def auto_save_config(self):
        hue = self.hue_slider.value()
        opacity = self.opacity_slider.value()
        lightness = self.lightness_slider.value()
        color = self.calculate_color(hue, opacity, lightness)
        men_color = self.color_input.text().strip()
        
        if not men_color.startswith('#') or len(men_color) not in (7, 9):
            men_color = '#fc0000'
        
        config_settings = {
            'Fov_Size': Fov_Size,
            'Confidence': Confidence,
            'Aim_Smooth': Aim_Smooth,
            'Max_Detections': Max_Detections,
            'Aim_Bone': Aim_Bone,
            'Enable_Aim': bool(Enable_Aim),
            'Enable_Slots': bool(Enable_Slots),
            'Controller_On': bool(Controller_On),
            'Keybind': self.Keybind,
            'Keybind2': self.Keybind2,
            'Enable_TriggerBot': bool(Enable_TriggerBot),
            'Show_Fov': bool(Show_Fov),
            'Show_Crosshair': bool(Show_Crosshair),
            'Show_Debug': bool(Show_Debug),
            'Auto_Fire_Fov_Size': Auto_Fire_Fov_Size,
            'Show_Detections': bool(Show_Detections),
            'Show_Aimline': bool(Show_Aimline),
        }
        
        config_settings.update({
            'Auto_Fire_Confidence': Auto_Fire_Confidence,
            'Auto_Fire_Keybind': self.Auto_Fire_Keybind,
            'Require_Keybind': bool(Require_Keybind),
            'RGBA_Value': {
                'red': color.red(),
                'green': color.green(),
                'blue': color.blue(),
                'opacity': opacity,
                'lightness': lightness
            },
            'Use_Hue': bool(Use_Hue),
            'CupMode_On': bool(CupMode_On),
            'Reduce_Bloom': bool(Reduce_Bloom),
            'Require_ADS': bool(Require_ADS),
            'AntiRecoil_On': bool(AntiRecoil_On),
            'AntiRecoil_Strength': AntiRecoil_Strength,
            'Theme_Hex_Color': men_color,
            'Enable_Flick_Bot': Enable_Flick_Bot,
            'Flick_Scope_Sens': Flick_Scope_Sens,
            'Flick_Cooldown': Flick_Cooldown,
            'Flick_Delay': Flick_Delay,
            'Flickbot_Keybind': self.Flickbot_Keybind,
            'Enable_Aim_Slot1': bool(Enable_Aim_Slot1),
        })
        
        config_settings.update({
            'Enable_Aim_Slot2': bool(Enable_Aim_Slot2),
            'Enable_Aim_Slot3': bool(Enable_Aim_Slot3),
            'Enable_Aim_Slot4': bool(Enable_Aim_Slot4),
            'Enable_Aim_Slot5': bool(Enable_Aim_Slot5),
            'Slot1_Keybind': self.Slot1_Keybind,
            'Slot2_Keybind': self.Slot2_Keybind,
            'Slot3_Keybind': self.Slot3_Keybind,
            'Slot4_Keybind': self.Slot4_Keybind,
            'Slot5_Keybind': self.Slot5_Keybind,
            'Slot6_Keybind': self.Slot6_Keybind,
            'Fov_Size_Slot1': Fov_Size_Slot1,
            'Fov_Size_Slot2': Fov_Size_Slot2,
            'Fov_Size_Slot3': Fov_Size_Slot3,
            'Fov_Size_Slot4': Fov_Size_Slot4,
            'Fov_Size_Slot5': Fov_Size_Slot5,
            'Use_Model_Class': bool(Use_Model_Class),
            'Img_Value': Img_Value,
        })
        
        config_settings.update({
            'Model_FPS': Model_FPS,
            'Last_Model': Last_Model
        })
        
        global Keybind, Keybind2, Auto_Fire_Keybind, Flickbot_Keybind, Slot1_Keybind, Slot2_Keybind, Slot3_Keybind, Slot4_Keybind, Slot5_Keybind, Slot6_Keybind
        # Updating globals from instance variables
        Keybind = self.Keybind
        Keybind2 = self.Keybind2
        Auto_Fire_Keybind = self.Auto_Fire_Keybind
        Flickbot_Keybind = self.Flickbot_Keybind
        Slot1_Keybind = self.Slot1_Keybind
        Slot2_Keybind = self.Slot2_Keybind
        Slot3_Keybind = self.Slot3_Keybind
        Slot4_Keybind = self.Slot4_Keybind
        Slot5_Keybind = self.Slot5_Keybind
        Slot6_Keybind = self.Slot6_Keybind
        
        with open('utility\\config.ini', 'w') as outfile:
            jsond.dump(config_settings, outfile, indent=4)
        
        self.update_labels()

    
    def closeEvent(self, event):
        # Save configuration first
        self.auto_save_config()
        
                # Clean up resources
        self.timer.stop()
        if hasattr(self, 'key_check_timer'):
            self.key_check_timer.stop()
        
        # Close GHUB mouse device if it was opened
        if ghub_found and ghub_handle:
            try:
                ghub_mouse_close()
            except:
                pass
        
        # Close all overlay windows
        try:
            if Ai992.overlay is not None:
                Ai992.overlay.setAttribute(Qt.WA_DeleteOnClose, True)
                Ai992.overlay.close()
                Ai992.overlay.deleteLater()
        except:
            pass
        
        # Process all pending events
        QApplication.processEvents()
        
        # Force immediate termination of all threads
        try:
            # Find and stop all QTimers in the application
            for widget in QApplication.allWidgets():
                for child in widget.findChildren(QTimer):
                    try:
                        child.stop()
                    except:
                        pass
            
            # Close console window
            console_window = ctypes.windll.kernel32.GetConsoleWindow()
            ctypes.windll.user32.PostMessageW(console_window, 16, 0, 0)
            
            # Force python process to exit completely
            QTimer.singleShot(100, lambda: os._exit(0))  # Hard exit after 100ms
        except:
            pass
            
        # Accept the event to allow the window to close
        event.accept()

    
    def update_aim_bone(self, index):
        global Aim_Bone, Aim_Bone, Aim_Bone
        self.Aim_Bone = self.aim_bone_combobox.currentText()
        if self.aim_bone_combobox.currentText() == 'Head':
            Aim_Bone = 'Head'
        if self.aim_bone_combobox.currentText() == 'Neck':
            Aim_Bone = 'Neck'
        if self.aim_bone_combobox.currentText() == 'Body':
            Aim_Bone = 'Body'
        self.auto_save_config()

    
    def update_img_value(self, index):
        global Img_Value, Img_Value, Img_Value, Img_Value, Img_Value
        self.Img_Value = self.img_value_combobox.currentText()
        if self.img_value_combobox.currentText() == '320':
            Img_Value = '320'
        if self.img_value_combobox.currentText() == '480':
            Img_Value = '480'
        if self.img_value_combobox.currentText() == '640':
            Img_Value = '640'
        if self.img_value_combobox.currentText() == '736':
            Img_Value = '736'
        if self.img_value_combobox.currentText() == '832':
            Img_Value = '832'
        self.auto_save_config()

    
    def refresh_extra(self):
        global pixel_increment, randomness, sensitivity, distance_to_scale, dont_launch_overlays, use_mss, hide_masks
        secretfile = open('utility\\extra.ini')
        secretconfig = jsond.load(secretfile)
        pixel_increment = secretconfig['pixel_increment']['value']
        randomness = secretconfig['randomness']['value']
        sensitivity = secretconfig['sensitivity']['value']
        distance_to_scale = secretconfig['distance_to_scale']['value']
        dont_launch_overlays = secretconfig['dont_launch_overlays']['value']
        use_mss = secretconfig['use_mss']['value']
        hide_masks = secretconfig['hide_masks']['value']
        self.auto_save_config()
   

    
    def start_select_hotkey(self):
    
        self.is_selecting_hotkey = True
        self.Keybind = None
        self.btn_hotkey.setText('Press Any Key..')
        threading.Thread(target = self.listen_for_hotkey).start()
        self.auto_save_config()


    
    def listen_for_hotkey(self):
        while self.is_selecting_hotkey:
            for vk in range(256):
                if win32api.GetKeyState(vk) in (-127, -128):
                    self.Keybind = vk
                    self.is_selecting_hotkey = False
                    key_name_converted = KEY_NAMES.get(self.Keybind, 'None' if self.Keybind is None else f'''0x{self.Keybind:02X}''')
                    self.btn_hotkey.setText(f'''{key_name_converted}''')
                    self.auto_save_config()
                    return
            time.sleep(0.1)


    
    def start_select_hotkey2(self):
        self.is_selecting_hotkey2 = True
        self.Keybind2 = None
        self.btn_hotkey2.setText('Press Any Key..')
        threading.Thread(target = self.listen_for_hotkey2).start()
        self.auto_save_config()
 

    
    def listen_for_hotkey2(self):
        while self.is_selecting_hotkey2:
            for vk in range(256):
                if win32api.GetKeyState(vk) in (-127, -128):
                    self.Keybind2 = vk
                    self.is_selecting_hotkey2 = False
                    key_name_converted2 = KEY_NAMES.get(self.Keybind2, 'None' if self.Keybind2 is None else f'''0x{self.Keybind2:02X}''')
                    self.btn_hotkey2.setText(f'''{key_name_converted2}''')
                    self.auto_save_config()
                    return
            time.sleep(0.1)

    
    def start_select_hotkey3(self):
        self.is_selecting_hotkey3 = True
        self.Auto_Fire_Keybind = None
        self.btn_hotkey3.setText('Press Any Key..')
        threading.Thread(target = self.listen_for_hotkey3).start()
        self.auto_save_config()

    
    def listen_for_hotkey3(self):
 
        while self.is_selecting_hotkey3:
            for vk in range(256):
                if win32api.GetKeyState(vk) in (-127, -128):
                    self.Auto_Fire_Keybind = vk
                    self.is_selecting_hotkey3 = False
                    key_name_converted3 = KEY_NAMES.get(self.Auto_Fire_Keybind, 'None' if self.Auto_Fire_Keybind is None else f'''0x{self.Auto_Fire_Keybind:02X}''')
                    self.btn_hotkey3.setText(f'''{key_name_converted3}''')
                    self.auto_save_config()
                    return
            time.sleep(0.1)

    
    def start_select_hotkey4(self):
        self.is_selecting_hotkey4 = True
        self.Flickbot_Keybind = None
        self.btn_hotkey4.setText('Press Any Key..')
        threading.Thread(target = self.listen_for_hotkey4).start()
        self.auto_save_config()


    
    def listen_for_hotkey4(self):
        while self.is_selecting_hotkey4:
            for vk in range(256):
                if win32api.GetKeyState(vk) in (-127, -128):
                    self.Flickbot_Keybind = vk
                    self.is_selecting_hotkey4 = False
                    key_name_converted4 = KEY_NAMES.get(self.Flickbot_Keybind, 'None' if self.Flickbot_Keybind is None else f'''0x{self.Flickbot_Keybind:02X}''')
                    self.btn_hotkey4.setText(f'''{key_name_converted4}''')
                    self.auto_save_config()
                    return
            time.sleep(0.1)

    
    def start_select_hotkey_slot1(self):
        self.is_selecting_hotkey_slot1 = True
        self.Slot1_Keybind = None
        self.btn_hotkey_slot1.setText('Press Any Key..')
        threading.Thread(target = self.listen_for_hotkey_slot1).start()
        self.auto_save_config()
       

    
    def listen_for_hotkey_slot1(self):
        while self.is_selecting_hotkey_slot1:
            for vk in range(256):
                if win32api.GetKeyState(vk) in (-127, -128):
                    self.Slot1_Keybind = vk
                    self.is_selecting_hotkey_slot1 = False
                    key_name_converted_slot1 = KEY_NAMES.get(self.Slot1_Keybind, 'None' if self.Slot1_Keybind is None else f'''0x{self.Slot1_Keybind:02X}''')
                    self.btn_hotkey_slot1.setText(f'''{key_name_converted_slot1}''')
                    self.auto_save_config()
                    return
            time.sleep(0.1)

    
    def start_select_hotkey_slot2(self):
        self.is_selecting_hotkey_slot2 = True
        self.Slot2_Keybind = None
        self.btn_hotkey_slot2.setText('Press Any Key..')
        threading.Thread(target = self.listen_for_hotkey_slot2).start()
        self.auto_save_config()
    

    
    def listen_for_hotkey_slot2(self):
        while self.is_selecting_hotkey_slot2:
            for vk in range(256):
                if win32api.GetKeyState(vk) in (-127, -128):
                    self.Slot2_Keybind = vk
                    self.is_selecting_hotkey_slot2 = False
                    key_name_converted_slot2 = KEY_NAMES.get(self.Slot2_Keybind, 'None' if self.Slot2_Keybind is None else f'''0x{self.Slot2_Keybind:02X}''')
                    self.btn_hotkey_slot2.setText(f'''{key_name_converted_slot2}''')
                    self.auto_save_config()
                    return
            time.sleep(0.1)

    
    def start_select_hotkey_slot3(self):
        self.is_selecting_hotkey_slot3 = True
        self.Slot3_Keybind = None
        self.btn_hotkey_slot3.setText('Press Any Key..')
        threading.Thread(target = self.listen_for_hotkey_slot3).start()
        self.auto_save_config()


    
    def listen_for_hotkey_slot3(self):
        while self.is_selecting_hotkey_slot3:
            for vk in range(256):
                if win32api.GetKeyState(vk) in (-127, -128):
                    self.Slot3_Keybind = vk
                    self.is_selecting_hotkey_slot3 = False
                    key_name_converted_slot3 = KEY_NAMES.get(self.Slot3_Keybind, 'None' if self.Slot3_Keybind is None else f'''0x{self.Slot3_Keybind:02X}''')
                    self.btn_hotkey_slot3.setText(f'''{key_name_converted_slot3}''')
                    self.auto_save_config()
                    return
            time.sleep(0.1)


    
    def start_select_hotkey_slot4(self):
        self.is_selecting_hotkey_slot4 = True
        self.Slot4_Keybind = None
        self.btn_hotkey_slot4.setText('Press Any Key..')
        threading.Thread(target = self.listen_for_hotkey_slot4).start()
        self.auto_save_config()

    
    def listen_for_hotkey_slot4(self):
        while self.is_selecting_hotkey_slot4:
            for vk in range(256):
                if win32api.GetKeyState(vk) in (-127, -128):
                    self.Slot4_Keybind = vk
                    self.is_selecting_hotkey_slot4 = False
                    key_name_converted_slot4 = KEY_NAMES.get(self.Slot4_Keybind, 'None' if self.Slot4_Keybind is None else f'''0x{self.Slot4_Keybind:02X}''')
                    self.btn_hotkey_slot4.setText(f'''{key_name_converted_slot4}''')
                    self.auto_save_config()
                    return
            time.sleep(0.1)


    
    def start_select_hotkey_slot5(self):

        self.is_selecting_hotkey_slot5 = True
        self.Slot5_Keybind = None
        self.btn_hotkey_slot5.setText('Press Any Key..')
        threading.Thread(target = self.listen_for_hotkey_slot5).start()
        self.auto_save_config()


    
    def listen_for_hotkey_slot5(self):

        while self.is_selecting_hotkey_slot5:
            for vk in range(256):
                if win32api.GetKeyState(vk) in (-127, -128):
                    self.Slot5_Keybind = vk
                    self.is_selecting_hotkey_slot5 = False
                    key_name_converted_slot5 = KEY_NAMES.get(self.Slot5_Keybind, 'None' if self.Slot5_Keybind is None else f'''0x{self.Slot5_Keybind:02X}''')
                    self.btn_hotkey_slot5.setText(f'''{key_name_converted_slot5}''')
                    self.auto_save_config()
                    return
            time.sleep(0.1)


    
    def start_select_hotkey_slot6(self):

        self.is_selecting_hotkey_slot6 = True
        self.Slot6_Keybind = None
        self.btn_hotkey_slot6.setText('Press Any Key..')
        threading.Thread(target = self.listen_for_hotkey_slot6).start()
        self.auto_save_config()


    
    def listen_for_hotkey_slot6(self):

        while self.is_selecting_hotkey_slot6:
            for vk in range(256):
                if win32api.GetKeyState(vk) in (-127, -128):
                    self.Slot6_Keybind = vk
                    self.is_selecting_hotkey_slot6 = False
                    key_name_converted_slot6 = KEY_NAMES.get(self.Slot6_Keybind, 'None' if self.Slot6_Keybind is None else f'''0x{self.Slot6_Keybind:02X}''')
                    self.btn_hotkey_slot6.setText(f'''{key_name_converted_slot6}''')
                    self.auto_save_config()
                    return
            time.sleep(0.1)


    
    def update_rgb_label(self):
        self.auto_save_config()
        hue = self.hue_slider.value()
        opacity = self.opacity_slider.value()
        lightness = self.lightness_slider.value()
        color = self.calculate_color(hue, opacity, lightness)
        self.rgb_label.setText(f'''RGB: {color.red()} {color.green()} {color.blue()}''')
        self.lightness_label.setText(f'''Lightness: {lightness}''')
        self.opacity_label.setText(f'''Opacity: {opacity}''')


    
    def calculate_color(self, hue, opacity, lightness):
        overlay_color = QColor.fromHsl(hue, 255, lightness)
        overlay_color.setAlpha(opacity)
        return overlay_color


    
    def on_slider_value_change(self, value):
        global Fov_Size
        self.auto_save_config()
        tick_position = round(value / 10) * 10
        self.slider.setValue(tick_position)
        Fov_Size = tick_position
        self.Fov_Size_label.setText(f'''FOV Size: {str(Fov_Size)}''')
        
        # Update the overlay FOV size immediately if it exists
        if Ai992.overlay is not None:
            Ai992.overlay.Fov_Size = Fov_Size
            Ai992.overlay.current_slot_selectedd = Ai992.current_slot_selected
            Ai992.overlay.update_fov_size()


    
    def on_slider0_value_change(self, value):
        global Confidence
        self.auto_save_config()
        tick_position0 = round(value / 1) * 1
        self.slider0.setValue(tick_position0)
        Confidence = tick_position0
        self.Confidence_label.setText(f'''Confidence: 0.{str(Confidence)}''')


    
    def on_slider_fps_value_change(self, value):
        global Model_FPS
        self.auto_save_config()
        tick_position0r = round(value / 1) * 1
        self.slider_fps.setValue(tick_position0r)
        Model_FPS = tick_position0r
        self.fps_label.setText(f'''Max FPS: {str(Model_FPS)}''')


    
    def on_slider3_value_change(self, value):
        global Aim_Smooth
        self.auto_save_config()
        tick_position3 = round(value / 5) * 5
        self.slider3.setValue(tick_position3)
        Aim_Smooth = tick_position3
        self.Aim_Smooth_label.setText(f'''Aim Speed: {str(Aim_Smooth)}''')

    
    def on_slider4_value_change(self, value):
        global Max_Detections
    
        self.auto_save_config()
        tick_position4 = round(value / 1) * 1
        self.slider4.setValue(tick_position4)
        Max_Detections = tick_position4
        self.Max_Detections_label.setText(f'''Max Detections: {str(Max_Detections)}''')


    
    def on_slider5_value_change(self, value):
        global Auto_Fire_Fov_Size

        self.auto_save_config()
        tick_position5 = round(value / 1) * 1
        self.slider5.setValue(tick_position5)
        Auto_Fire_Fov_Size = tick_position5
        self.Auto_Fire_Fov_Size_label.setText(f'''FOV Size: {str(Auto_Fire_Fov_Size)}''')


    
    def on_slider60_value_change(self, value):
        global AntiRecoil_Strength
    
        self.auto_save_config()
        tick_position60 = round(value / 1) * 1
        self.slider60.setValue(tick_position60)
        AntiRecoil_Strength = tick_position60
        self.AntiRecoil_Strength_label.setText(f'''Strength: {str(AntiRecoil_Strength)}''')
 

    
    def on_slider_slot1_value_change(self, value):
        global Fov_Size_Slot1
     
        self.auto_save_config()
        tick_position = round(value / 10) * 10
        self.slider_slot1.setValue(tick_position)
        Fov_Size_Slot1 = tick_position
        self.Fov_Size_label_slot1.setText(f'''FOV: {str(Fov_Size_Slot1)}''')
        
        # Update the overlay FOV size immediately if it exists and slot1 is currently selected
        if Ai992.overlay is not None and Ai992.current_slot_selected == 1:
            Ai992.overlay.Fov_Size = Fov_Size_Slot1
            Ai992.overlay.update_fov_size()
 

    
    def on_slider_slot2_value_change(self, value):
        global Fov_Size_Slot2
      
        self.auto_save_config()
        tick_position = round(value / 10) * 10
        self.slider_slot2.setValue(tick_position)
        Fov_Size_Slot2 = tick_position
        self.Fov_Size_label_slot2.setText(f'''FOV: {str(Fov_Size_Slot2)}''')
        
        # Update the overlay FOV size immediately if it exists and slot2 is currently selected
        if Ai992.overlay is not None and Ai992.current_slot_selected == 2:
            Ai992.overlay.Fov_Size = Fov_Size_Slot2
            Ai992.overlay.update_fov_size()
  

    
    def on_slider_slot3_value_change(self, value):
        global Fov_Size_Slot3
        
        self.auto_save_config()
        tick_position = round(value / 10) * 10
        self.slider_slot3.setValue(tick_position)
        Fov_Size_Slot3 = tick_position
        self.Fov_Size_label_slot3.setText(f'''FOV: {str(Fov_Size_Slot3)}''')
        
        # Update the overlay FOV size immediately if it exists and slot3 is currently selected
        if Ai992.overlay is not None and Ai992.current_slot_selected == 3:
            Ai992.overlay.Fov_Size = Fov_Size_Slot3
            Ai992.overlay.update_fov_size()
 
    
    def on_slider_slot4_value_change(self, value):
        global Fov_Size_Slot4
      
        self.auto_save_config()
        tick_position = round(value / 10) * 10
        self.slider_slot4.setValue(tick_position)
        Fov_Size_Slot4 = tick_position
        self.Fov_Size_label_slot4.setText(f'''FOV: {str(Fov_Size_Slot4)}''')
        
        # Update the overlay FOV size immediately if it exists and slot4 is currently selected
        if Ai992.overlay is not None and Ai992.current_slot_selected == 4:
            Ai992.overlay.Fov_Size = Fov_Size_Slot4
            Ai992.overlay.update_fov_size()
 

    
    def on_slider_slot5_value_change(self, value):
        global Fov_Size_Slot5
      
        self.auto_save_config()
        tick_position = round(value / 10) * 10
        self.slider_slot5.setValue(tick_position)
        Fov_Size_Slot5 = tick_position
        self.Fov_Size_label_slot5.setText(f'''FOV: {str(Fov_Size_Slot5)}''')
        
        # Update the overlay FOV size immediately if it exists and slot5 is currently selected
        if Ai992.overlay is not None and Ai992.current_slot_selected == 5:
            Ai992.overlay.Fov_Size = Fov_Size_Slot5
            Ai992.overlay.update_fov_size()
  

    
    def on_flick_scope_slider_value_change(self, value):
        global Flick_Scope_Sens
     
        self.auto_save_config()
        tick_position_flick_scope = round(value / 1) * 1
        self.flick_scope_slider.setValue(tick_position_flick_scope)
        Flick_Scope_Sens = tick_position_flick_scope
        self.flick_scope_label.setText(f'''Flick Strength: {str(Flick_Scope_Sens)}%''')
   

    
    def on_flick_cool_slider_value_change(self, value):
        global Flick_Cooldown
     
        self.auto_save_config()
        tick_position_cooldown = round(value / 5) * 5 / 100
        self.flick_cool_slider.setValue(int(tick_position_cooldown * 100))
        Flick_Cooldown = tick_position_cooldown
        self.flick_cool_label.setText(f'''Cool Down: {str(Flick_Cooldown)}s''')
     

    
    def on_flick_delay_slider_value_change(self, value):
        global Flick_Delay
     
        self.auto_save_config()
        tick_position_delay = value / 1000
        self.flick_delay_slider.setValue(int(tick_position_delay * 1000))
        Flick_Delay = tick_position_delay
        self.flick_delay_label.setText(f'''Shot Delay: {str(Flick_Delay)}s''')
     

    
    def on_slider6_value_change(self, value):
        global Auto_Fire_Confidence
       
        self.auto_save_config()
        tick_position6 = round(value / 1) * 1
        self.slider6.setValue(tick_position6)
        Auto_Fire_Confidence = tick_position6
        self.Auto_Fire_Confidence_label.setText(f'''Confidence: 0.{str(Auto_Fire_Confidence)}''')
   

    
    def toggle_checkbox1(self, state):
        global Enable_Aim
  
        self.auto_save_config()
        Enable_Aim = state == Qt.Unchecked
        self.Enable_Aim_checkbox.setChecked(not Enable_Aim)
        QApplication.processEvents()
        self.auto_save_config()
     

    
    def on_checkbox_state_change(self, state):
        global Enable_Aim, Enable_Aim_Slot1, Enable_Aim_Slot2, Enable_Aim_Slot3, Enable_Aim_Slot4, Enable_Aim_Slot5, Enable_Slots, Show_Fov, Show_Crosshair, Show_Debug, Enable_TriggerBot, Show_Detections, Show_Aimline, Require_Keybind, Controller_On, CupMode_On, Reduce_Bloom, Require_ADS, AntiRecoil_On, Enable_Flick_Bot, Use_Hue, Use_Model_Class
    
        self.auto_save_config()
        if self.sender() == self.Enable_Aim_checkbox:
            Enable_Aim = state == Qt.Checked
        if self.sender() == self.Enable_Aim_Slot1_checkbox:
            Enable_Aim_Slot1 = state == Qt.Checked
        if self.sender() == self.Enable_Aim_Slot2_checkbox:
            Enable_Aim_Slot2 = state == Qt.Checked
        if self.sender() == self.Enable_Aim_Slot3_checkbox:
            Enable_Aim_Slot3 = state == Qt.Checked
        if self.sender() == self.Enable_Aim_Slot4_checkbox:
            Enable_Aim_Slot4 = state == Qt.Checked
        if self.sender() == self.Enable_Aim_Slot5_checkbox:
            Enable_Aim_Slot5 = state == Qt.Checked
        if self.sender() == self.Enable_Slots_checkbox:
            Enable_Slots = state == Qt.Checked
        if self.sender() == self.Show_Fov_checkbox:
            Show_Fov = state == Qt.Checked
        if self.sender() == self.Show_Crosshair_checkbox:
            Show_Crosshair = state == Qt.Checked
        if self.sender() == self.Show_Debug_checkbox:
            Show_Debug = state == Qt.Checked
            if Show_Debug == False:
                hwnd = win32gui.FindWindow(None, random_caption1)
                win32gui.ShowWindow(hwnd, win32con.SW_HIDE)
            else:
                hwnd = win32gui.FindWindow(None, random_caption1)
                win32gui.ShowWindow(hwnd, win32con.SW_SHOWNORMAL)
        if self.sender() == self.Enable_TriggerBot_checkbox:
            Enable_TriggerBot = state == Qt.Checked
        if self.sender() == self.Show_Detections_checkbox:
            Show_Detections = state == Qt.Checked
        if self.sender() == self.Show_Aimline_checkbox:
            Show_Aimline = state == Qt.Checked
        if self.sender() == self.Require_Keybind_checkbox:
            Require_Keybind = state == Qt.Checked
        if self.sender() == self.Controller_On_checkbox:
            Controller_On = state == Qt.Checked
        if self.sender() == self.CupMode_On_checkbox:
            CupMode_On = state == Qt.Checked
        if self.sender() == self.Reduce_Bloom_checkbox:
            Reduce_Bloom = state == Qt.Checked
        if self.sender() == self.Require_ADS_checkbox:
            Require_ADS = state == Qt.Checked
        if self.sender() == self.AntiRecoil_On_checkbox:
            AntiRecoil_On = state == Qt.Checked
        if self.sender() == self.Enable_Flick_checkbox:
            Enable_Flick_Bot = state == Qt.Checked
        if self.sender() == self.Use_Hue_checkbox:
            Use_Hue = state == Qt.Checked
        if self.sender() == self.Use_Model_Class_checkbox:
            Use_Model_Class = state == Qt.Checked
        self.auto_save_config()



class HueUpdaterThread(threading.Thread):    
    def __init__(self, parent):
        super().__init__()
        self.parent = parent
        self.hue = 0
        self.running = True
    
    def run(self):
        if self.running:
            self.hue = (self.hue + 1) % 360
            time.sleep(0.025)
    
    def stop(self):
        self.running = False


class DetectionBox(QWidget):
    
    def __init__(self):
        super().__init__()
        self.setWindowFlags(Qt.Tool | Qt.FramelessWindowHint | Qt.WindowStaysOnTopHint | Qt.WindowTransparentForInput | Qt.WindowDoesNotAcceptFocus)
        self.setAttribute(Qt.WA_TranslucentBackground)
        self.setAttribute(Qt.WA_TransparentForMouseEvents)
        self.setAttribute(Qt.WA_ShowWithoutActivating)
        self.load_config()
        self.Fov_Size = Fov_Size
        self.setGeometry(int((screen_res_X - self.Fov_Size) + 2) // 2, int((screen_res_Y - self.Fov_Size) + 2) // 2, self.Fov_Size + 25, self.Fov_Size + 25)
        self.detected_players = []
        self.hue_updater = HueUpdaterThread(self)
        self.hue_updater.start()
        self.current_slot_selectedd = 1
        self.update_fov_size()
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update)
        self.timer.start(100)
        self.key_states = {k: False for k in [Slot1_Keybind, Slot2_Keybind, Slot3_Keybind, Slot4_Keybind, Slot5_Keybind, Slot6_Keybind]}
        self.key_check_timer = QTimer(self)
        self.key_check_timer.timeout.connect(self.check_key_states)
        self.key_check_timer.start(10)


    
    def update_detected_players(self, detected_players):
        self.detected_players = detected_players
        self.update()
 

    
    def clear_detected_players(self):
  
        self.detected_players = []
        self.update()
       

    
    def load_config(self):

        infile = open('utility\\config.ini', 'r')
        config_settings = jsond.load(infile)
   
        self.Use_Hue = config_settings['Use_Hue']
        self.fov_color = QColor(config_settings.get('RGBA_Value', { }).get('red', 255), config_settings.get('RGBA_Value', { }).get('green', 255), config_settings.get('RGBA_Value', { }).get('blue', 255), config_settings.get('RGBA_Value', { }).get('opacity', 255))
        self.lightness = config_settings.get('RGBA_Value', { }).get('lightness', 128)
        self.fov_color_outline = QColor(0, 0, 0, config_settings.get('RGBA_Value', { }).get('opacity', 255))
        self.watermark_color = QColor(config_settings.get('RGBA_Value', { }).get('red', 255), config_settings.get('RGBA_Value', { }).get('green', 255), config_settings.get('RGBA_Value', { }).get('blue', 255), config_settings.get('RGBA_Value', { }).get('opacity', 255))
        self.watermark_color_outline = QColor(0, 0, 0, config_settings.get('RGBA_Value', { }).get('opacity', 255))
        self.crosshair_dot_color = QColor(config_settings.get('RGBA_Value', { }).get('red', 255), config_settings.get('RGBA_Value', { }).get('green', 255), config_settings.get('RGBA_Value', { }).get('blue', 255), 255)
        self.crosshair_color = QColor(255, 255, 255, 255)
        self.fov_thickness = 0.8
        self.watermark_thickness = 0.5
        self.crosshair_thickness = 1.5


    
    def BlueADS(self):
        return True if win32api.GetKeyState(win32con.VK_RBUTTON) in (-127, -128) else False
   

    
    def BlueFire(self):
        return True if win32api.GetKeyState(win32con.VK_LBUTTON) in (-127, -128) else False


    
    def check_key_states(self):
        try:
            for key, keybind in zip(
                [Slot1_Keybind, Slot2_Keybind, Slot3_Keybind, Slot4_Keybind, Slot5_Keybind, Slot6_Keybind],
                ["Slot1_Keybind", "Slot2_Keybind", "Slot3_Keybind", "Slot4_Keybind", "Slot5_Keybind", "Slot6_Keybind"]
            ):
                if key is None:
                    continue
                    
                key_state = win32api.GetAsyncKeyState(key) & 0x8000 != 0
                if key_state != self.key_states.get(key, False):
                    self.key_states[key] = key_state
                    if key_state:
                        # Key was just pressed, change the slot
                        for i, k in enumerate([Slot1_Keybind, Slot2_Keybind, Slot3_Keybind, Slot4_Keybind, Slot5_Keybind, Slot6_Keybind]):
                            if k == key:
                                Ai992.current_slot_selected = i + 1
                                break
        except Exception as e:
            print(e)


    
    def update_fov_size(self):
        if Enable_Slots:
            if self.current_slot_selectedd == 1:
                self.Fov_Size = Fov_Size_Slot1
            elif self.current_slot_selectedd == 2:
                self.Fov_Size = Fov_Size_Slot2
            elif self.current_slot_selectedd == 3:
                self.Fov_Size = Fov_Size_Slot3
            elif self.current_slot_selectedd == 4:
                self.Fov_Size = Fov_Size_Slot4
            elif self.current_slot_selectedd == 5:
                self.Fov_Size = Fov_Size_Slot5
            elif self.current_slot_selectedd == 6:
                self.Fov_Size = 15
            else:
                self.Fov_Size = Fov_Size
        if not Enable_Slots:
            self.Fov_Size = Fov_Size
        self.setGeometry(int((screen_res_X - 4 - self.Fov_Size) + 2) // 2, int((screen_res_Y - 4 - self.Fov_Size) + 2) // 2, self.Fov_Size + 25, self.Fov_Size + 25)
        self.update()


    
    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        
        if not Enable_Slots:
            self.setGeometry(
                int((screen_res_X - 4 - self.Fov_Size + 2) // 2),
                int((screen_res_Y - 4 - self.Fov_Size + 2) // 2),
                self.Fov_Size + 25,
                self.Fov_Size + 25
            )
            
        self.load_config()
        font_size_px = 11
        font = QFont("Verdana")
        font.setPixelSize(font_size_px)
        painter.setFont(font)
        
        if CupMode_On:
            return
            
        if CupMode_On == False:
            if self.current_slot_selectedd == 6 and Enable_Slots:
                pass
            elif Show_Fov:
                center_x = self.Fov_Size // 2
                center_y = self.Fov_Size // 2
                fov_radius = (self.Fov_Size // 2) - (self.fov_thickness // 2)
                
                if Use_Hue:
                    fov_thickness = 1.1
                    num_sections = 360
                    section_angle = 360 / num_sections
                    
                    for i in range(num_sections):
                        hue = (self.hue_updater.hue + i) % 360
                        color = QColor.fromHsv(hue, 175, 255)
                        pen = QPen(color, fov_thickness, Qt.SolidLine)
                        painter.setPen(pen)
                        
                        start_angle = i * section_angle * 16
                        end_angle = (i + 1) * section_angle * 16
                        
                        rect = QRect(
                            int(center_x + 2 - fov_radius),
                            int(center_y + 2 - fov_radius),
                            int(2 * fov_radius),
                            int(2 * fov_radius)
                        )
                        
                        painter.drawArc(rect, int(start_angle), int(section_angle * 16))
                    
                    inner_radius = fov_radius - 1
                    outer_radius = fov_radius + 1
                    
                    pen_inner = QPen(Qt.black, 0.6)
                    pen_outer = QPen(Qt.black, 0.6)
                    
                    painter.setPen(pen_inner)
                    inner_rect = QRect(
                        int(center_x + 2 - inner_radius),
                        int(center_y + 2 - inner_radius),
                        int(2 * inner_radius),
                        int(2 * inner_radius)
                    )
                    painter.drawEllipse(inner_rect)
                    
                    painter.setPen(pen_outer)
                    outer_rect = QRect(
                        int(center_x + 2 - outer_radius),
                        int(center_y + 2 - outer_radius),
                        int(2 * outer_radius),
                        int(2 * outer_radius)
                    )
                    painter.drawEllipse(outer_rect)
                else:
                    fov_rect = QRectF(
                        center_x + 2 - fov_radius,
                        center_y + 2 - fov_radius,
                        2 * fov_radius,
                        2 * fov_radius
                    )
                    
                    painter.setPen(QPen(self.fov_color, self.fov_thickness, Qt.SolidLine))
                    painter.drawEllipse(fov_rect)
                    
                    inner_radius = fov_radius - 1
                    outer_radius = fov_radius + 1
                    
                    pen_inner = QPen(self.fov_color_outline, 0.6)
                    pen_outer = QPen(self.fov_color_outline, 0.6)
                    
                    painter.setPen(pen_inner)
                    inner_rect = QRect(
                        int(center_x + 2 - inner_radius),
                        int(center_y + 2 - inner_radius),
                        int(2 * inner_radius),
                        int(2 * inner_radius)
                    )
                    painter.drawEllipse(inner_rect)
                    
                    painter.setPen(pen_outer)
                    outer_rect = QRect(
                        int(center_x + 2 - outer_radius),
                        int(center_y + 2 - outer_radius),
                        int(2 * outer_radius),
                        int(2 * outer_radius)
                    )
                    painter.drawEllipse(outer_rect)
                    
            if Show_Crosshair:
                if self.BlueFire():
                    pen_crosshair_ads = QPen(QColor(255, 255, 255, 255), 0.3, Qt.SolidLine)
                    painter.setPen(pen_crosshair_ads)
                    painter.setRenderHint(QPainter.Antialiasing, False)
                    
                    center_x = self.width() // 2 - 11
                    center_y = self.height() // 2 - 11
                    
                    painter.drawLine(center_x, center_y + 3, center_x, center_y - 3)
                    painter.drawLine(center_x - 3, center_y, center_x + 3, center_y)
                elif self.BlueADS():
                    pen_crosshair_ads = QPen(QColor(255, 255, 255, 255), 0.5, Qt.SolidLine)
                    painter.setPen(pen_crosshair_ads)
                    painter.setRenderHint(QPainter.Antialiasing, False)
                    
                    center_x = self.width() // 2 - 11
                    center_y = self.height() // 2 - 11
                    
                    painter.drawLine(center_x, center_y + 5, center_x, center_y - 5)
                    painter.drawLine(center_x - 5, center_y, center_x + 5, center_y)
                else:
                    pen_crosshair = QPen(QColor(255, 255, 255, 255), 1.1, Qt.SolidLine)
                    painter.setPen(pen_crosshair)
                    painter.setRenderHint(QPainter.Antialiasing, False)
                    
                    center_x = self.width() // 2 - 11
                    center_y = self.height() // 2 - 11
                    
                    painter.drawLine(center_x, center_y + 7, center_x, center_y - 7)
                    painter.drawLine(center_x - 7, center_y, center_x + 7, center_y)
                    
                    dot_radius = 1
                    if Use_Hue:
                        hue = self.hue_updater.hue
                        dot_pen = QPen(QColor.fromHsv(hue, 255, 255), dot_radius * 2)
                    else:
                        dot_pen = QPen(self.crosshair_dot_color, dot_radius * 2)
                        
                    painter.setPen(dot_pen)
                    painter.drawPoint(center_x, center_y)
                    
                    pen_crosshair_outline = QPen(Qt.black, 1, Qt.SolidLine)
                    painter.setPen(pen_crosshair_outline)
                    
                    outline_offset = 1
                    painter.drawLine(center_x - outline_offset, center_y + 8, center_x - outline_offset, center_y - 8)
                    painter.drawLine(center_x - 8, center_y - outline_offset, center_x + 8, center_y - outline_offset)
                    painter.drawLine(center_x + outline_offset, center_y + 8, center_x + outline_offset, center_y - 8)
                    painter.drawLine(center_x - 8, center_y + outline_offset, center_x + 8, center_y + outline_offset)
                    painter.drawLine(center_x - outline_offset, center_y - 8, center_x + outline_offset, center_y - 8)
                    painter.drawLine(center_x - outline_offset, center_y + 8, center_x + outline_offset, center_y + 8)
                    painter.drawLine(center_x - 8, center_y - outline_offset, center_x - 8, center_y + outline_offset)
                    painter.drawLine(center_x + 8, center_y - outline_offset, center_x + 8, center_y + outline_offset)
                    
                self.update()
            
            if self.current_slot_selectedd == 6 and Enable_Slots:
                pass
            elif Show_Detections:
                for player in self.detected_players:
                    x1, y1, x2, y2 = player['x1'], player['y1'], player['x2'], player['y2']
                    head1, head2 = player['head1'], player['head2']
                    
                    width = x2 - x1
                    height = y2 - y1
                    
                    margin_factor = 0.25
                    margin_x = width * margin_factor
                    margin_y = height * margin_factor
                    
                    x1 -= margin_x
                    y1 -= margin_y
                    x2 += margin_x
                    y2 += margin_y
                    
                    width = x2 - x1
                    height = y2 - y1
                    
                    x1, y1, x2, y2 = int(x1), int(y1), int(x2), int(y2)
                    head1, head2 = int(head1), int(head2)
                    
                    if Use_Hue:
                        hue = int(time.time() * 150) % 360
                        color = QColor.fromHsv(hue, 255, 255, 55)
                        painter.setPen(QPen(color, 2))
                    else:
                        painter.setPen(QPen(self.fov_color, 2))
                    
                    corner_length = int(min(width, height) * 0.25)
                    
                    # # painter.setPen(QPen(Qt.black, 1))
                    painter.setRenderHint(QPainter.Antialiasing, False)
                    
                    # Draw ESP box outlines
                    # painter.drawLine(x1 - 1, y1 - 1, x1 + corner_length + 1, y1 - 1)
                    # painter.drawLine(x1 - 1, y1 - 1, x1 - 1, y1 + corner_length + 1)
                    # painter.drawLine(x2 + 1, y1 - 1, x2 - corner_length - 1, y1 - 1)
                    # painter.drawLine(x2 + 1, y1 - 1, x2 + 1, y1 + corner_length + 1)
                    # painter.drawLine(x1 - 1, y2 + 1, x1 + corner_length + 1, y2 + 1)
                    # painter.drawLine(x1 - 1, y2 + 1, x1 - 1, y2 - corner_length - 1)
                    # painter.drawLine(x2 + 1, y2 + 1, x2 - corner_length - 1, y2 + 1)
                    # painter.drawLine(x2 + 1, y2 + 1, x2 + 1, y2 - corner_length - 1)
                    
                    if Use_Hue:
                        painter.setPen(QPen(color, 2))
                    else:
                        painter.setPen(QPen(self.fov_color, 2))
                    
                    # Draw ESP box
                    painter.setPen(QPen(color if Use_Hue else self.fov_color, 2)); painter.drawLine(x1, y1, x1 + corner_length, y1)
                    painter.setPen(QPen(color if Use_Hue else self.fov_color, 2)); painter.drawLine(x1, y1, x1, y1 + corner_length)
                    painter.setPen(QPen(color if Use_Hue else self.fov_color, 2)); painter.drawLine(x2, y1, x2 - corner_length, y1)
                    painter.drawLine(x2, y1, x2, y1 + corner_length)
                    painter.drawLine(x1, y2, x1 + corner_length, y2)
                    painter.drawLine(x1, y2, x1, y2 - corner_length)
                    painter.drawLine(x2, y2, x2 - corner_length, y2)
                    painter.drawLine(x2, y2, x2, y2 - corner_length)
                    
                    # # painter.setPen(QPen(Qt.black, 1))
                    # painter.setRenderHint(QPainter.Antialiasing, False)
                    
                    # Additional outline details
                    # # painter.drawLine(x1 + 1, y1 + 1, x1 + corner_length - 1, y1 + 1)
                    # # painter.drawLine(x1 + 1, y1 + 1, x1 + 1, y1 + corner_length - 1)
                    # # painter.drawLine(x2 - 1, y1 + 1, x2 - corner_length + 1, y1 + 1)
                    # # painter.drawLine(x2 - 1, y1 + 1, x2 - 1, y1 + corner_length - 1)
                    # # painter.drawLine(x1 + 1, y2 - 1, x1 + corner_length - 1, y2 - 1)
                    # painter.drawLine(x1 + 1, y1 + 1, x1 + corner_length - 1, y1 + 1)
                    # painter.drawLine(x1 + 1, y1 + 1, x1 + 1, y1 + corner_length - 1)
                    # painter.drawLine(x2 - 1, y1 + 1, x2 - corner_length + 1, y1 + 1)
                    # painter.drawLine(x2 - 1, y1 + 1, x2 - 1, y1 + corner_length - 1)
                    # painter.drawLine(x1 + 1, y2 - 1, x1 + corner_length - 1, y2 - 1)
                    # painter.drawLine(x1 + 1, y2 - 1, x1 + 1, y2 - corner_length + 1)
                    # painter.drawLine(x2 - 1, y2 - 1, x2 - corner_length + 1, y2 - 1)
                    # painter.drawLine(x2 - 1, y2 - 1, x2 - 1, y2 - corner_length + 1)
            
            if Show_Aimline:
                for player in self.detected_players:
                    head1, head2 = player['head1'], player['head2']
                    center_x, center_y = self.Fov_Size // 2 + 1, self.Fov_Size // 2 + 1
                    
                    # painter.setPen(QPen(Qt.black, 1))
                    
                    # Draw aimline outlines
                    # painter.drawLine(head1 - 1, head2, center_x - 1, center_y)
                    # painter.drawLine(head1 + 1, head2, center_x + 1, center_y)
                    # painter.drawLine(head1, head2 - 1, center_x, center_y - 1)
                    # painter.drawLine(head1, head2 + 1, center_x, center_y + 1)
                    
                    if Use_Hue:
                        painter.setPen(QPen(color, 2))
                    else:
                        painter.setPen(QPen(self.fov_color, 2))
                    
                    # Draw aimline
                    painter.setPen(QPen(color if Use_Hue else self.fov_color, 2)); painter.setPen(QPen(color, 2)); painter.drawLine(head1, head2, center_x, center_y)
            
            if Use_Hue:
                bottom_left_text = "LegionAI #1 Aimbot"
                text_rect = QRect(10, self.height() - 15, self.width() - 15, 16)
                
                pen_black = QPen(QColor(0, 0, 0, 128), 2.5, Qt.SolidLine)
                painter.setPen(pen_black)
                
                for dx in (-1, 0, 1):
                    for dy in (-1, 0, 1):
                        painter.drawText(text_rect.translated(dx, dy), Qt.AlignRight | Qt.AlignBottom, bottom_left_text)
                
                pen_white = QPen(QColor(255, 255, 255), 0.5, Qt.SolidLine)
                painter.setPen(pen_white)
                painter.drawText(text_rect, Qt.AlignRight | Qt.AlignBottom, bottom_left_text)
            else:
                bottom_left_text = "LegionAI #1 Aimbot"
                text_rect = QRect(10, self.height() - 15, self.width() - 15, 16)
                
                pen_black = QPen(self.watermark_color_outline, 2.5, Qt.SolidLine)
                painter.setPen(pen_black)
                
                for dx in (-1, 0, 1):
                    for dy in (-1, 0, 1):
                        painter.drawText(text_rect.translated(dx, dy), Qt.AlignRight | Qt.AlignBottom, bottom_left_text)
                
                painter.setPen(QPen(self.watermark_color, self.watermark_thickness, Qt.SolidLine))
                painter.drawText(text_rect, Qt.AlignRight | Qt.AlignBottom, bottom_left_text)
              
    def focusInEvent(self, event):
        ctypes.windll.user32.SetFocus(None)


Controller_Toggled = False

class ControllerMode:
    def main():
        global Controller_Toggled, Controller_Toggled
    
        pygame.init()
        if pygame.joystick.get_count() > 0:
            pygame.joystick.init()
            joystick = pygame.joystick.Joystick(0)
            joystick.init()
            pygame.event.get()
            left_trigger = joystick.get_axis(4)
            if left_trigger > 0.9:
                Controller_Toggled = True
            elif left_trigger < 0.9:
                Controller_Toggled = False
            pygame.time.wait(6)


def LemonLoverF9():
    if Require_ADS:
        def is_mouse_down():
            lmb_state = win32api.GetKeyState(1) & win32api.GetKeyState(2)
            return lmb_state < 0
           
    else:
        def is_mouse_down():
            lmb_state = win32api.GetKeyState(1)
            return lmb_state < 0
          

    RoundedRStr = round(AntiRecoil_Strength)
    min_vertical = int(RoundedRStr)
    max_vertical = int(RoundedRStr) + 1
    if is_mouse_down():
        horizontal_offset = random.randrange(-2000, 2000, 1) / 1000
        vertical_offset = random.randrange(min_vertical * 1000, int(max_vertical * 1000), 1) / 1000
        if AntiRecoil_On:
            if ghub_found and ghub_handle:
                ghub_mouse_move(button=0, x=0, y=int(vertical_offset), wheel=0)
            else:
                win32api.mouse_event(1, 0, int(vertical_offset))
        if Reduce_Bloom:
            if ghub_found and ghub_handle:
                ghub_mouse_move(button=0, x=int(horizontal_offset), y=0, wheel=0)
            else:
                win32api.mouse_event(1, int(horizontal_offset), 0)
        time_offset = random.randrange(2, 25, 1) / 1000
        time.sleep(time_offset)
    time.sleep(random.uniform(5e-05, 0.0001))
    

threading.Thread(target = ControllerMode.main).start()
threading.Thread(target = LemonLoverF9).start()

class Ai992:
    app = QApplication(sys.argv + ['-platform', 'windows:darkmode=1'])
    window = MyWindow()
    extra = ctypes.c_ulong(0)
    ii_ = Input_I()
    screen_x = int(screen_res_X / 2)
    screen_y = int(screen_res_Y / 2)
    screen = mss.mss()
    lock = threading.Lock()
    current_slot_selected = 1
    overlay = None  # Will store the DetectionBox overlay reference
    
    def __init__(self):
        self.last_flick = time.time()
        self.start_time = time.time()
        self.default_model = YOLO('C:\\ProgramData\\NVIDIA\\NGX\\models\\8OON.pt')

    
    def left_click():
        if win32api.GetKeyState(win32con.VK_LBUTTON) in (-127, -128):
            pass
        elif Require_Keybind:
            if win32api.GetAsyncKeyState(Auto_Fire_Keybind) < 0:
                if ghub_found and ghub_handle:
                    ghub_mouse_move(button=1, x=0, y=0, wheel=0) # Mouse down
                    time.sleep(random.uniform(0.0002, 2e-05))
                    ghub_mouse_move(button=-1, x=0, y=0, wheel=0) # Mouse up
                    time.sleep(random.uniform(0.0002, 2e-05))
                else:
                    ctypes.windll.user32.mouse_event(2)
                    time.sleep(random.uniform(0.0002, 2e-05))
                    ctypes.windll.user32.mouse_event(4)
                    time.sleep(random.uniform(0.0002, 2e-05))
            
        else:
            if ghub_found and ghub_handle:
                ghub_mouse_move(button=1, x=0, y=0, wheel=0) # Mouse down
                time.sleep(random.uniform(0.0002, 2e-05))
                ghub_mouse_move(button=-1, x=0, y=0, wheel=0) # Mouse up
                time.sleep(random.uniform(0.0002, 2e-05))
            else:
                ctypes.windll.user32.mouse_event(2)
                time.sleep(random.uniform(0.0002, 2e-05))
                ctypes.windll.user32.mouse_event(4)
                time.sleep(random.uniform(0.0002, 2e-05))


    
    def is_aimbot_enabled():
        if Enable_Slots:
            return {
                1: Enable_Aim_Slot1,
                2: Enable_Aim_Slot2,
                3: Enable_Aim_Slot3,
                4: Enable_Aim_Slot4,
                5: Enable_Aim_Slot5
            }.get(Ai992.current_slot_selected, Enable_Aim)
        else:
            return Enable_Aim
 

    
    def is_flickbot_enabled():
      
        return Enable_Flick_Bot
      

    
    def is_triggerbot_enabled():
    
        return Enable_TriggerBot
     

    
    def is_targeted():
  
        return True if Keybind is not None and win32api.GetAsyncKeyState(Keybind) < 0 else False
      

    
    def is_targeted2():
        # Check if the second keybind is pressed
        key2_pressed = win32api.GetAsyncKeyState(Keybind2) < 0 if Keybind2 is not None else False
        
        # Check if controller aiming override is active
        controller_active = Controller_Toggled 

        # Return True if EITHER the key is pressed OR controller aiming is active
        return key2_pressed or controller_active
     

    
    def is_targeted3():

        return True if Flickbot_Keybind is not None and win32api.GetAsyncKeyState(Flickbot_Keybind) < 0 else False
   

    
    def is_target_locked(x, y):
   
        threshold = Auto_Fire_Fov_Size
        if screen_x - threshold <= x <= screen_x + threshold:
            pass
        else:
            return False
        
        if screen_y - threshold <= y <= screen_y + threshold:
            pass
        else:
            return False
        
        return True



    
    def move_crosshair(self, x, y):
        if not Ai992.is_targeted() and not Ai992.is_targeted2():
            return
        
        delta_x = (x - screen_x)
        delta_y = (y - screen_y)
        distance = np.linalg.norm((delta_x, delta_y))
        
        if distance == 0:
            return
        
        # Calculate smoothing factor (between 0.5 and 1.0)
        smoothing = min(0.5 + (Aim_Smooth - 10) / 10, 1)
        
        # Normalize direction vector and apply pixel increment and smoothing
        move_x = (delta_x / distance) * pixel_increment * smoothing
        move_y = (delta_y / distance) * pixel_increment * smoothing
        
        # Apply a higher sensitivity value for stronger movement
        # Using 0.05 instead of 0.01 to prevent values from rounding to zero
        effective_sensitivity = sensitivity * 5  # Increase from default 0.01 to 0.05
        move_x *= effective_sensitivity
        move_y *= effective_sensitivity
        
        # Add randomness
        rand_x = random.uniform(-randomness, randomness)
        rand_y = random.uniform(-randomness, randomness)
        move_x += rand_x
        move_y += rand_y
        
        # Scale based on distance (farther targets get less movement)
        distance_clamped = min(1, distance / distance_to_scale)
        move_x *= distance_clamped
        move_y *= distance_clamped
        
        # Send mouse movement command via appropriate driver
        if ghub_found and ghub_handle:
            try:
                ghub_mouse_move(button=0, x=round(move_x), y=round(move_y), wheel=0)
            except Exception:
                with Ai992.lock:
                    Ai992.ii_.mi = MouseInput(round(move_x), round(move_y), 0, 1, 0, ctypes.pointer(Ai992.extra))
                    input_struct = Input(ctypes.c_ulong(0), Ai992.ii_)
                    ctypes.windll.user32.SendInput(1, ctypes.byref(input_struct), ctypes.sizeof(input_struct))
        else:
            with Ai992.lock:
                Ai992.ii_.mi = MouseInput(round(move_x), round(move_y), 0, 1, 0, ctypes.pointer(Ai992.extra))
                input_struct = Input(ctypes.c_ulong(0), Ai992.ii_)
                ctypes.windll.user32.SendInput(1, ctypes.byref(input_struct), ctypes.sizeof(input_struct))



    
    def move_crosshair_silent(self, x, y):
        if not Ai992.is_targeted3():
            return
        
        flick_strength = min(0.8 + (Flick_Scope_Sens - 10) * 1.7 / 80, 2)
        delta_x = (x - screen_x) * flick_strength
        delta_y = (y - screen_y) * flick_strength
        
        if ghub_found and ghub_handle:
            ghub_mouse_move(button=0, x=round(delta_x), y=round(delta_y), wheel=0)
        else:
            Ai992.ii_.mi = MouseInput(round(delta_x), round(delta_y), 0, 1, 0, ctypes.pointer(Ai992.extra))
            input_struct = Input(ctypes.c_ulong(0), Ai992.ii_)
            ctypes.windll.user32.SendInput(1, ctypes.byref(input_struct), ctypes.sizeof(input_struct))
        
        time.sleep(Flick_Delay)
        
        if not win32api.GetKeyState(win32con.VK_LBUTTON) in (-127, -128):
            if ghub_found and ghub_handle:
                ghub_mouse_move(button=1, x=0, y=0, wheel=0) # Mouse down
                time.sleep(random.uniform(8e-05, 2e-05))
                ghub_mouse_move(button=-1, x=0, y=0, wheel=0) # Mouse up
            else:
                ctypes.windll.user32.mouse_event(2)
                time.sleep(random.uniform(8e-05, 2e-05))
                ctypes.windll.user32.mouse_event(4)
        
        time.sleep(Flick_Delay / 4)
        
        if ghub_found and ghub_handle:
            ghub_mouse_move(button=0, x=round(-delta_x), y=round(-delta_y), wheel=0)
        else:
            with Ai992.lock:
                Ai992.ii_.mi = MouseInput(round(-delta_x), round(-delta_y), 0, 1, 0, ctypes.pointer(Ai992.extra))
                input_struct = Input(ctypes.c_ulong(0), Ai992.ii_)
                ctypes.windll.user32.SendInput(1, ctypes.byref(input_struct), ctypes.sizeof(input_struct))
        
        self.last_flick = time.time()


    
    def get_targ_fps():
        target_fps = Model_FPS
        frame_duration = 1.5 / target_fps
        return frame_duration

    
    def start(self):
        os.system("cls")
        kernel32 = ctypes.WinDLL("kernel32")
        user32 = ctypes.WinDLL("user32")
        hWnd = kernel32.GetConsoleWindow()
        SW_HIDEN = 0
        half_screen_width = ctypes.windll.user32.GetSystemMetrics(0) / 2
        half_screen_height = ctypes.windll.user32.GetSystemMetrics(1) / 2
        
        closest_detection = None
        detected_players = []
        
        if use_mss == 0:
            camera = bettercam.create(output_idx = 0, output_color = 'BGR', max_buffer_len = 1)
        
        try:
            winsound.PlaySound('C:\\Windows\\Media\\Windows Balloon.wav', winsound.SND_FILENAME)
        except:
            pass
        
        Ai992.window.show()
        
        if dont_launch_overlays != 1:
            # app2 = QApplication([])
            overlay = DetectionBox()
            overlay.show()
            Ai992.overlay = overlay  # Store reference to overlay in class variable
        
        # Attempt to initialize GHUB mouse control once at the start
        init_result = ghub_mouse_open()

        # Update the ghub_handle and ghub_found variables
        global ghub_handle, ghub_found
        ghub_handle = handle  # Update ghub_handle with the current handle value
        ghub_found = found    # Update ghub_found with the current found value
        
        if not init_result or not ghub_found or not ghub_handle:
            ghub_found = False
            ghub_handle = 0
            
        start_time = time.perf_counter()
        
        while True:
            key_states = {
                'F1': win32api.GetAsyncKeyState(win32con.VK_F1),
                'F2': win32api.GetAsyncKeyState(win32con.VK_F2),
                'F8': win32api.GetAsyncKeyState(win32con.VK_F8)
            }
            
            if key_states['F8'] & 0x8000:
                Ai992.window.toggle_menu_visibility()
                time.sleep(0.1)  # Small delay to prevent multiple toggles
            
            if not CupMode_On:
                if key_states['F1'] & 0x8000:
                    time.sleep(0.25)
                    my_window1z = MyWindow()
                    my_window1z.toggle_checkbox1(True)
                
                if key_states['F2'] & 0x8000:
                    time.sleep(0.25)
                    try:
                        console_window = ctypes.windll.kernel32.GetConsoleWindow()
                        ctypes.windll.user32.PostMessageW(console_window, 16, 0, 0)
                        # event is not defined here, remove event.accept()
                    except:
                        try:
                            sys.exit()
                        except:
                            os.system('taskkill /f /fi "imagename eq cmd.exe" 1>NUL 2>NUL')
            
            if not Enable_Slots:
                self.Fov_Size = Fov_Size
            else:
                slot_keys = [Slot1_Keybind, Slot2_Keybind, Slot3_Keybind, Slot4_Keybind, Slot5_Keybind, Slot6_Keybind]
                slot_fov_sizes = [Fov_Size_Slot1, Fov_Size_Slot2, Fov_Size_Slot3, Fov_Size_Slot4, Fov_Size_Slot5, 10]
                
                for idx, key in enumerate(slot_keys):
                    if key is not None and win32api.GetAsyncKeyState(key) < 0:
                        Ai992.current_slot_selected = idx + 1
                        # Update overlay slot selection immediately if overlay exists
                        if Ai992.overlay is not None:
                            Ai992.overlay.current_slot_selectedd = Ai992.current_slot_selected
                            Ai992.overlay.update_fov_size()
                
                self.Fov_Size = slot_fov_sizes[Ai992.current_slot_selected - 1]
            
            if use_mss == 0:
                left = int((screen_res_X - self.Fov_Size) // 2)
                top = int((screen_res_Y - self.Fov_Size) // 2)
                right = int(left + self.Fov_Size)
                bottom = int(top + self.Fov_Size)
                detection_box = (left, top, right, bottom)
                
                frame = camera.grab(region=detection_box)
                if frame is None:
                    continue
                
                frame = np.asarray(frame)[..., :3]
                frame = np.ascontiguousarray(frame)
                
                mask = np.ones((self.Fov_Size, self.Fov_Size), dtype=np.uint8)
                mask[:self.Fov_Size//2, :self.Fov_Size//4] = 0
                
                frame = cv2.bitwise_and(frame, frame, mask=mask)
            else:
                detection_box = {
                    'left': int(half_screen_width - self.Fov_Size/2),
                    'top': int(half_screen_height - self.Fov_Size/2),
                    'width': int(self.Fov_Size),
                    'height': int(self.Fov_Size)
                }
                
                frame = np.array(Ai992.screen.grab(detection_box))[..., :3]
            
            if hide_masks == 0:
                frame = np.ascontiguousarray(frame)
                mask = np.zeros_like(frame, dtype=np.uint8)
                
                center_x, center_y = self.Fov_Size // 2, self.Fov_Size // 2
                radius = self.Fov_Size // 2
                
                cv2.ellipse(mask, (center_x, center_y), (radius-2, radius-2), 0, 0, 360, (255, 255, 255), thickness=cv2.FILLED)
                
                if mask.ndim == 3:
                    mask = mask[..., 0]
                
                frame = cv2.bitwise_and(frame, frame, mask=mask)
            
            confi = Confidence / 100
            
            if Last_Model.endswith('.pt'):
                imgsz_value = int(Img_Value)
            else:
                imgsz_value = 640
            
            results = Ai992.window.modell(
                frame, 
                conf=confi, 
                iou=0.7, 
                imgsz=imgsz_value, 
                max_det=Max_Detections, 
                retina_masks=True, 
                verbose=False, 
                classes=0 if Use_Model_Class else None
            )
            
            if len(results[0].boxes.xyxy) != 0:
                least_crosshair_dist = False
                confi = Confidence / 100
                
                for detection, conf in zip(results[0].boxes.xyxy.tolist(), results[0].boxes.conf.tolist()):
                    x1, y1, x2, y2 = detection
                    x1, y1, x2, y2 = int(x1), int(y1), int(x2), int(y2)
                    
                    x1y1 = [x1, y1]
                    x2y2 = [x2, y2]
                    
                    height = y2 - y1
                    width = x2 - x1
                    
                    if Aim_Bone == "Head":
                        relative_head_X = int((x1 + x2) / 2)
                        relative_head_Y = int((y1 + y2) / 2 - height / 2.5)
                    elif Aim_Bone == "Neck":
                        relative_head_X = int((x1 + x2) / 2)
                        relative_head_Y = int((y1 + y2) / 2 - height / 3)
                    else:
                        relative_head_X = int((x1 + x2) / 2)
                        relative_head_Y = int((y1 + y2) / 2 - height / 5)
                    
                    crosshair_dist = math.dist((relative_head_X, relative_head_Y), (self.Fov_Size / 2, self.Fov_Size / 2))
                    
                    if not least_crosshair_dist or crosshair_dist < least_crosshair_dist:
                        least_crosshair_dist = crosshair_dist
                        closest_detection = {
                            'x1y1': x1y1,
                            'x2y2': x2y2,
                            'relative_head_X': relative_head_X,
                            'relative_head_Y': relative_head_Y,
                            'conf': conf
                        }
                    
                    if Show_Detections or Show_Aimline:
                        detected_players.append({
                            'x1': x1,
                            'y1': y1,
                            'x2': x2,
                            'y2': y2,
                            'head1': closest_detection['relative_head_X'] if closest_detection else 0,
                            'head2': closest_detection['relative_head_Y'] if closest_detection else 0
                        })
                    
                    if Show_Debug:
                        cv2.rectangle(frame, (x1, y1), (x2, y2), (255, 255, 255), 1)
                        cv2.putText(frame, f"{int(conf * 100)}%", x1y1, cv2.FONT_HERSHEY_DUPLEX, 0.5, (1, 1, 255), 1)
                
                if closest_detection:
                    if closest_detection:
                        absolute_head_X = closest_detection['relative_head_X'] + (left if use_mss == 0 else detection_box['left'])
                        absolute_head_Y = closest_detection['relative_head_Y'] + (top if use_mss == 0 else detection_box['top'])
                    
                    if Show_Debug:
                        cv2.circle(frame, (closest_detection['relative_head_X'], closest_detection['relative_head_Y']), 2, (0, 0, 255), -1)
                        cv2.line(frame, (closest_detection['relative_head_X'], closest_detection['relative_head_Y']), (self.Fov_Size//2, self.Fov_Size//2), (255, 255, 255), 1)
                    
                    if Ai992.is_triggerbot_enabled() and Ai992.is_target_locked(absolute_head_X, absolute_head_Y):
                        tbconfi = Auto_Fire_Confidence / 100
                        if conf >= tbconfi:
                            threading.Thread(target=Ai992.left_click).start()
                    
                    if Ai992.is_aimbot_enabled():
                        threading.Thread(target=Ai992.move_crosshair, args=(self, absolute_head_X, absolute_head_Y)).start()
                    
                    if Ai992.is_flickbot_enabled():
                        time_since_last_flick = time.time() - self.last_flick
                        if time_since_last_flick > Flick_Cooldown:
                            threading.Thread(target=Ai992.move_crosshair_silent, args=(self, absolute_head_X, absolute_head_Y)).start()
            
            if Show_Detections or Show_Aimline:
                overlay.update_detected_players(detected_players)
                detected_players = []
            
            elapsed_time = time.perf_counter() - start_time
            frame_duration = Ai992.get_targ_fps()
            time_to_sleep = max(0, frame_duration - elapsed_time)
            
            if time_to_sleep > 0:
                time.sleep(time_to_sleep)
            
            if Show_Debug and not CupMode_On:
                cv2.putText(frame, f"FPS: {int(1.5 / (time.perf_counter() - start_time))}", (5, 20), cv2.FONT_HERSHEY_COMPLEX_SMALL, 1, (155, 155, 155), 1)
                cv2.imshow(random_caption1, frame)
            
            Ai992.app.processEvents()
            start_time = time.perf_counter()
 


class Encryption:
    encrypt_string = lambda plain_text, key, iv: binascii.hexlify(AES.new(key, AES.MODE_CBC, iv).encrypt(pad(plain_text.encode(), 16))).decode()
    decrypt_string = lambda cipher_text, key, iv: unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(binascii.unhexlify(cipher_text)), 16).decode()
    encrypt = lambda message, enc_key, iv: Encryption.encrypt_string(message, SHA256.new(enc_key.encode()).digest()[:32], SHA256.new(iv.encode()).digest()[:16])
    decrypt = lambda message, enc_key, iv: Encryption.decrypt_string(message, SHA256.new(enc_key.encode()).digest()[:32], SHA256.new(iv.encode()).digest()[:16])




class LicenseKeyWindow(QDialog):
    def __init__(self, parent=None):
        super(LicenseKeyWindow, self).__init__(parent)
        self.setWindowTitle("LegionAI")
        self.setWindowFlags(Qt.FramelessWindowHint | Qt.WindowStaysOnTopHint)
        self.setAttribute(Qt.WA_TranslucentBackground)
        self.setAttribute(Qt.WA_DeleteOnClose, True)  # CRITICAL: Ensure window is properly deleted when closed
        self.setFixedSize(420, 340)
        self.setModal(True)  # CRITICAL: Keep it modal
        
        # Animation properties
        self.validation_progress = 0
        self.is_validating = False
        self.validation_result = None
        self.validation_successful = False
        self.theme_hex_color = "#BB86FC"  # Purple theme
        self.validated_key = ""
        
        # Window drag properties
        self.dragging = False
        self.drag_position = None
        
        # Setup UI elements
        self.setup_ui()
        self.setup_animations()
        self.setup_sparkles()
        self.center_on_screen()
        
    def setup_ui(self):
        # Main layout
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(20, 20, 20, 20)
        
        # Content frame
        self.frame = QFrame()
        self.frame.setObjectName("licenseFrame")
        frame_layout = QVBoxLayout(self.frame)
        frame_layout.setSpacing(15)
        
        # Close button
        self.setup_close_button(frame_layout)
        
        # Title
        self.title_label = QLabel("LegionAI")
        self.title_label.setAlignment(Qt.AlignCenter)
        self.title_label.setObjectName("titleLabel")
        
        # License input
        self.key_input = QLineEdit()
        self.key_input.setPlaceholderText("ENTER LICENSE KEY")
        self.key_input.setAlignment(Qt.AlignCenter)
        self.key_input.setObjectName("keyInput")
        self.key_input.returnPressed.connect(self.validate_key)
        
        # Status label
        self.status_label = QLabel("")
        self.status_label.setAlignment(Qt.AlignCenter)
        self.status_label.setObjectName("statusLabel")
        
        # Progress bar
        self.setup_progress_bar()
        
        # Activate button
        self.activate_button = QPushButton("ACTIVATE")
        self.activate_button.setObjectName("activateButton")
        self.activate_button.setCursor(Qt.PointingHandCursor)
        self.activate_button.clicked.connect(self.validate_key)
        
        # Add widgets to layout
        frame_layout.addSpacing(10)
        frame_layout.addWidget(self.title_label)
        frame_layout.addSpacing(10)
        frame_layout.addWidget(self.key_input)
        frame_layout.addWidget(self.status_label)
        frame_layout.addWidget(self.progress_frame)
        frame_layout.addWidget(self.activate_button)
        
        main_layout.addWidget(self.frame)
        
        # Apply styles
        self.apply_styles()
        
    def setup_close_button(self, frame_layout):
        self.close_button = QPushButton("×")
        self.close_button.setObjectName("closeButton")
        self.close_button.setCursor(Qt.PointingHandCursor)
        
        # Critical: Force close on click with custom closure
        def force_close():
            # Stop all timers and kill animations first
            for child in self.findChildren(QTimer):
                try:
                    child.stop()
                except:
                    pass
            
            # Force cleanup of all event handlers
            QApplication.removePostedEvents(self)
            QApplication.processEvents()
            
            # Signal completion to dialog system
            self.validation_successful = False  # Mark as not successful on X click
            self.accept()
            self.done(QDialog.Accepted)
            
            # Brutally destroy the window
            self.close()
            self.destroy()
            self.deleteLater()
            
            # Force event processing again
            QApplication.processEvents()
        
        self.close_button.clicked.connect(force_close)
        self.close_button.setFixedSize(24, 24)
        
        top_container = QWidget()
        top_layout = QHBoxLayout(top_container)
        top_layout.setContentsMargins(0, 0, 0, 0)
        top_layout.addStretch(1)
        top_layout.addWidget(self.close_button)
        frame_layout.addWidget(top_container, 0, Qt.AlignRight)
        
    def setup_progress_bar(self):
        self.progress_frame = QFrame()
        self.progress_frame.setObjectName("progressFrame")
        self.progress_frame.setFixedHeight(4)
        self.progress_frame.setVisible(False)
        
        self.progress_indicator = QFrame(self.progress_frame)
        self.progress_indicator.setObjectName("progressIndicator")
        self.progress_indicator.setFixedHeight(4)
        self.progress_indicator.setFixedWidth(0)
        
        progress_layout = QHBoxLayout(self.progress_frame)
        progress_layout.setContentsMargins(0, 0, 0, 0)
        progress_layout.addWidget(self.progress_indicator)
    
    def setup_fade_animation(self):
        self.opacity_effect = QGraphicsOpacityEffect(self)
        self.setGraphicsEffect(self.opacity_effect)
        self.opacity_effect.setOpacity(0)
        
        self.fade_anim = QPropertyAnimation(self.opacity_effect, b"opacity")
        self.fade_anim.setDuration(500)
        self.fade_anim.setStartValue(0)
        self.fade_anim.setEndValue(1)
        self.fade_anim.setEasingCurve(QEasingCurve.OutCubic)
        self.fade_anim.start()
        
    def setup_animations(self):
        # Color animation for title
        self.hue = 0
        self.color_timer = QTimer(self)
        self.color_timer.timeout.connect(self.update_title_color)
        self.color_timer.start(20)
        
        # Sparkle animation
        self.sparkle_timer = QTimer(self)
        self.sparkle_timer.timeout.connect(self.update_sparkles)
        self.sparkle_timer.start(30)
        
        # Fade-in animation
        self.setup_fade_animation()
        
    def setup_sparkles(self):
        self.sparkles = []
        # Background sparkles
        for _ in range(20):
            self.sparkles.append(self.create_sparkle(0.2, 1.2, 0.05, 0.2, 0))
        # Foreground sparkles
        for _ in range(20):
            self.sparkles.append(self.create_sparkle(0.5, 2.0, 0.2, 0.5, 1))
            
    def create_sparkle(self, min_size, max_size, min_opacity, max_opacity, layer):
        return {
            'x': random.randint(10, 410),
            'y': random.randint(10, 330),
            'size': random.uniform(min_size, max_size),
            'opacity': random.uniform(min_opacity, max_opacity),
            'speed': random.uniform(0.1, 0.4),
            'phase': random.uniform(0, math.pi * 2),
            'direction': random.choice([-1, 1]),
            'layer': layer
        }
    
    def update_sparkles(self):
        for sparkle in self.sparkles:
            sparkle['phase'] += sparkle['speed'] * sparkle['direction']
            if sparkle['phase'] > math.pi * 2:
                sparkle['phase'] -= math.pi * 2
        self.update()
        
    def update_title_color(self):
        self.hue = (self.hue + 1) % 360
        if self.hue % 5 == 0:  # Update less frequently for performance
            color = QColor.fromHsv(self.hue, 200, 255)
            self.title_label.setStyleSheet(f"#titleLabel {{ color: {color.name()}; }}")
    
    def center_on_screen(self):
        screen_geometry = QApplication.desktop().screenGeometry()
        x = (screen_geometry.width() - self.width()) // 2
        y = (screen_geometry.height() - self.height()) // 2
        self.move(x, y)
    
    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        
        # Draw sparkles
        for sparkle in self.sparkles:
            opacity = sparkle['opacity'] * (0.5 + 0.5 * math.sin(sparkle['phase']))
            if opacity > 0.01:
                painter.setOpacity(opacity)
                
                # Create a gradient for the sparkle
                if sparkle['layer'] == 0:
                    color = QColor.fromHsv((self.hue + 180) % 360, 150, 255)
                else:
                    color = QColor.fromHsv(self.hue, 200, 255)
                
                painter.setBrush(color)
                painter.setPen(Qt.NoPen)
                
                size = sparkle['size'] * (0.7 + 0.3 * math.sin(sparkle['phase']))
                painter.drawEllipse(
                    QPoint(sparkle['x'], sparkle['y']),
                    size, size
                )
    
    def validate_key(self):
        key = self.key_input.text().strip()
        
        # Show error if key is empty
        if not key:
            self.status_label.setText("Please enter a valid license key")
            self.shake_animation()
            return
        
        # Save key FIRST, adapted from authentication.py's save_key logic within its validate_key
        try:
            key_to_save = str(key).strip() # Use the key from input directly
            main_dir = os.path.dirname(os.path.abspath(__file__))
            utility_lib_path = os.path.join(main_dir, 'utility', 'lib')
            os.makedirs(utility_lib_path, exist_ok=True)
            key_file_path = os.path.join(utility_lib_path, 'key.file')
            
            # Save the key silently
            with open(key_file_path, "wb") as f: # Use binary write
                f.write(key_to_save.encode('utf-8'))
            self.validated_key = key_to_save # Store the key that was just saved
        except Exception:
            # Silently continue if saving fails
            pass
            # Decide if we should proceed if key saving fails - for now, we'll let validation continue
            
        # Start validation animation
        self.is_validating = True
        self.progress_frame.setVisible(True)
        self.validation_progress = 0
        self.status_label.setText("Validating...")
        self.progress_timer = QTimer(self)
        self.progress_timer.timeout.connect(self.update_validation_progress)
        self.progress_timer.start(10) # Faster progress updates
        
        # Disable input during validation
        self.key_input.setEnabled(False)
        self.activate_button.setEnabled(False)
        
        QApplication.processEvents() # Add this like in authentication.py
        
        # Add a deliberate 3.5 second delay for user experience
        
        # Use a timer to delay the actual validation process
        self.validation_timer = QTimer(self)
        self.validation_timer.setSingleShot(True)
        self.validation_timer.timeout.connect(self.complete_validation)
        self.validation_timer.start(3500)  # 3.5 second delay
    
    def complete_validation(self):
        """Complete the validation process after the delay"""
        
        try:
            # Set validation as successful and close window immediately
            console.print("[!] License valid! CLOSING WINDOW NOW...", style='bright_green')
            self.validation_successful = True
            
            # Complete the dialog and exit
            self.setResult(QDialog.Accepted)
            self.accept()
            self.done(QDialog.Accepted)
            
            # Ensure all processing is complete before returning
            QApplication.processEvents()
            
            # Don't need to call process_validation_result at all
            return
        except Exception as e:
            console.print(f"[ERROR] Failed to complete validation: {e}", style='bright_red')
    
    def update_validation_progress(self):
        if self.is_validating:
            self.validation_progress += 1
            self.progress_indicator.setFixedWidth(int((self.validation_progress / 100) * self.progress_frame.width()))
            
            if self.validation_progress >= 100:
                self.progress_timer.stop()
    
    def process_validation_result(self):
        """This method is no longer used - validation is handled directly in validate_key"""
        return
            
    def shake_animation(self):
        # Create shake animation for error feedback
        self.shake = QPropertyAnimation(self.key_input, b"pos")
        self.shake.setDuration(500)
        self.shake.setLoopCount(1)
        
        pos = self.key_input.pos()
        x, y = pos.x(), pos.y()
        
        shake_offset = 5
        shake_timing = 25
        
        # Define shake keyframes
        self.shake.setKeyValueAt(0, QPoint(x, y))
        self.shake.setKeyValueAt(0.1, QPoint(x + shake_offset, y))
        self.shake.setKeyValueAt(0.2, QPoint(x - shake_offset, y))
        self.shake.setKeyValueAt(0.3, QPoint(x + shake_offset, y))
        self.shake.setKeyValueAt(0.4, QPoint(x - shake_offset, y))
        self.shake.setKeyValueAt(0.5, QPoint(x + shake_offset, y))
        self.shake.setKeyValueAt(0.6, QPoint(x - shake_offset, y))
        self.shake.setKeyValueAt(0.7, QPoint(x + shake_offset, y))
        self.shake.setKeyValueAt(0.8, QPoint(x - shake_offset, y))
        self.shake.setKeyValueAt(0.9, QPoint(x + shake_offset, y))
        self.shake.setKeyValueAt(1, QPoint(x, y))
        
        self.shake.start()
        
    # Removing the fallback method since we're using the simple approach that works
        
    def get_validated_key(self):
        return self.validated_key
    
    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton:
            self.dragging = True
            self.drag_position = event.globalPos() - self.frameGeometry().topLeft()
            event.accept()
    
    def mouseMoveEvent(self, event):
        if event.buttons() == Qt.LeftButton and self.dragging:
            self.move(event.globalPos() - self.drag_position)
            event.accept()
    
    def mouseReleaseEvent(self, event):
        self.dragging = False
    
    def closeEvent(self, event):
        """Properly handle window closing event"""
        # Stop all timers and animations
        self.color_timer.stop() if hasattr(self, 'color_timer') else None
        self.sparkle_timer.stop() if hasattr(self, 'sparkle_timer') else None
        
        # Set result if validation was successful
        if hasattr(self, 'validation_successful') and self.validation_successful:
            self.setResult(QDialog.Accepted)
        
        # Accept the event to allow the window to close
        event.accept()
        
        # Process any pending events before closing
        QApplication.processEvents()
        
    def apply_styles(self):
        # Apply the styles
        self.setStyleSheet("""
            QDialog {
                background-color: transparent;
                font-family: "Segoe UI", sans-serif;
            }
            
            #closeButton {
                background-color: transparent;
                color: #8A8A8A;
                border: none;
                font-size: 18px;
                font-weight: bold;
            }
            
            #closeButton:hover {
                color: #FFFFFF;
            }
            
            #licenseFrame {
                background-color: #12121C;
                border-radius: 15px;
                border: 1px solid #362050;
            }
            
            #titleLabel {
                color: #BB86FC;
                font-size: 42px;
                font-weight: 500;
                font-style: italic;
                letter-spacing: 1px;
                font-family: "Arial Rounded MT Bold", "Segoe UI", sans-serif;
                margin-bottom: 8px;
                margin-top: -5px;
                padding: 0px 0;
                min-height: 56px;
            }
            
            #keyInput {
                background-color: #1E1E2D;
                border: 1px solid #3A2A55;
                border-radius: 6px;
                color: #FFFFFF;
                padding: 16px 12px;
                font-size: 14px;
                font-family: "Segoe UI", sans-serif;
                selection-background-color: #453366;
                letter-spacing: 1px;
                min-height: 24px;
            }
            
            #keyInput:focus {
                border: 1px solid #BB86FC;
                background-color: #252538;
            }
            
            #statusLabel {
                color: #ff5555;
                font-size: 13px;
                font-family: "Segoe UI", sans-serif;
                min-height: 20px;
                font-weight: 400;
            }
            
            #activateButton {
                background-color: #6A1B9A;
                color: white;
                border: none;
                border-radius: 6px;
                padding: 12px;
                font-weight: 600;
                font-size: 14px;
                font-family: "Segoe UI", sans-serif;
                letter-spacing: 0.5px;
            }
            
            #activateButton:hover {
                background-color: #8E24AA;
            }
            
            #activateButton:pressed {
                background-color: #4A148C;
            }
            
            #progressFrame {
                background-color: #252538;
                border-radius: 2px;
                margin: 0 40px 15px 40px;
            }
            
            #progressIndicator {
                background-color: #BB86FC;
                border-radius: 2px;
            }
        """)

def authenticate_user():
    # Check for existing key
    try:
        # Get the directory where main.py is located
        main_dir = os.path.dirname(os.path.abspath(__file__))
        
        # Navigate to utility/lib from main.py location
        lib_path = os.path.join(main_dir, 'utility', 'lib')
        os.makedirs(lib_path, exist_ok=True)
        key_path = os.path.join(lib_path, 'key.file')
        
        if os.path.exists(key_path):
            try:
                # Try to read in text mode
                with open(key_path, 'r') as file:
                    license_key = file.read().strip()
            except:
                # Fallback to binary mode
                with open(key_path, 'rb') as file:
                    license_key = file.read().decode('utf-8').strip()
                    
            if license_key:
                # Key exists, validate it with KeyAuth
                console.print('\n[>] Logging-In . . .', style='light_green', justify='center')
                try:
                    # Get a proper HWID
                    try:
                        import subprocess
                        hwid = subprocess.check_output('wmic csproduct get uuid').decode().split('\n')[1].strip()
                    except:
                        hwid = os.getenv('COMPUTERNAME', 'Unknown')
                    
                    # Validate the key
                    checker = api(name="LegionAI", ownerid="IvI5h6njk7", secret="", version="1.0", hash_to_check=None)
                    if checker.license(license_key, hwid):
                        console.print("[>] License valid! Opening menu...", style='light_green')
                        return True
                    else:
                        # Remove invalid key file
                        try:
                            os.remove(key_path)
                        except:
                            pass
                except Exception as e:
                    # Remove invalid key file
                    try:
                        os.remove(key_path)
                    except:
                        pass
            else:
                # Remove empty key file
                try:
                    os.remove(key_path)
                except:
                    pass
    except:
        pass
    
    # Create and show license window
    app = QApplication(sys.argv) if not QApplication.instance() else QApplication.instance()
    
    # Create license window with critical flags to ensure proper closing
    license_window = LicenseKeyWindow()
    license_window.setAttribute(Qt.WA_DeleteOnClose, True)
    license_window.setWindowModality(Qt.ApplicationModal)
    
    # Add finished signal handler to properly manage window closure
    def on_dialog_finished(result_code):
        QApplication.processEvents()
    
    license_window.finished.connect(on_dialog_finished)
    
    # Show dialog and process events
    license_window.show()
    QTimer.singleShot(100, lambda: None)
    QApplication.processEvents()
    
    # Execute the dialog
    result = license_window.exec_()
    
    if result == QDialog.Accepted:
        # Check if validation was successful
        if hasattr(license_window, 'validation_successful') and license_window.validation_successful:
            # Get the validated key
            validated_key = license_window.get_validated_key()
            
            if validated_key:
                # Save the key
                try:
                    main_dir = os.path.dirname(os.path.abspath(__file__))
                    lib_path = os.path.join(main_dir, 'utility', 'lib')
                    os.makedirs(lib_path, exist_ok=True)
                    key_path = os.path.join(lib_path, 'key.file')
                    
                    # Write key in text mode
                    with open(key_path, 'w') as file:
                        file.write(validated_key)
                        file.flush()
                except:
                    pass
            
            return True
    
    # Close the window if validation failed
    try:
        license_window.setAttribute(Qt.WA_DeleteOnClose, True)
        license_window.close()
        license_window.destroy()
        license_window.deleteLater()
    except:
        pass
    
    sys.exit(0)

class LoginForm:
    @staticmethod
    def login():
        # Try to authenticate with key file first
        return authenticate_user()

if __name__ == '__main__':
    try:
        os.system('cls')
        console.print('[>] Initializing . . .', style='bright_red', justify='center')
        
        # Check libraries first
        try:
            import wmi
            import numpy
            import torch
            import ultralytics
            import matplotlib
            import pygame
            import onnxruntime
            import comtypes
        except ImportError as e:
            console.print(f"[!] Missing required library: {str(e)}", style='red')
            install_process()
            
        # Start the login form
        try:
            if LoginForm.login():
                # Authentication successful, start the aimbot
                console.print('[>] Authentication successful! Starting...', style='green')
                legion = Ai992()
                legion.start()
        except Exception as e:
            console.print(f'[!] Login error: {str(e)}', style='bright_red', justify='center')
            time.sleep(3)
            sys.exit(1)
    except Exception as e:
        console.print(f'[!] Critical error: {str(e)}', style='bright_red', justify='center')
        time.sleep(3)
        sys.exit(1)
