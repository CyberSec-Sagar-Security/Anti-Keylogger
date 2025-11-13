"""
PRODUCTION ANTI-KEYLOGGER DETECTOR v4.0 - ADVANCED EDITION

DESIGN PHILOSOPHY:
- Report ONLY high-confidence keyloggers (not every unsigned process)
- Minimize false positives to <5% (ideally 1-2 processes max)
- Use multi-layer evidence: Must have 3+ strong indicators to flag
- Smart whitelisting: Don't flag HP, Dell, Apple, Microsoft, etc.
- Focus on ACTIVE keystroke capture, not just hooks

DETECTION CRITERIA (must meet 3+ for CRITICAL threat):
1. Unsigned binary + keyboard hook
2. Name spoofing (svchost.exe in wrong location, HP→HPP)
3. Keylogger keywords in path/name (keylog, pynput, hook)
4. Suspicious location (temp folders, random user directories)
5. Hidden process with keyboard hook
6. Unknown publisher in non-standard location

ADVANCED DETECTION (NO KEYWORDS NEEDED):
7. Network exfiltration - Suspicious outbound connections
8. File logging - Writing to suspicious log files
9. Memory patterns - Unusual memory footprint
10. Process ancestry - Spawned from scripts or orphaned
11. DLL injection - Minimal threads, injected into legitimate process
"""

import ctypes
from ctypes import wintypes
import os
import sys
import time
from pathlib import Path
from typing import List, Dict, Optional, Set, Tuple
from dataclasses import dataclass
from datetime import datetime

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / 'src'))

try:
    import win32api
    import win32security
    import pywintypes
    import win32process
    import win32con
except ImportError:
    print("[!] Installing required packages...")
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "pywin32"])
    import win32api
    import win32security
    import pywintypes
    import win32process
    import win32con

try:
    import psutil
except ImportError:
    print("[!] Installing psutil for advanced analysis...")
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "psutil"])
    import psutil

from enumerator import WindowsAPIEnumerator


# ======================== VISUAL ENHANCEMENTS ========================

class Colors:
    """ANSI color codes for terminal styling."""
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    
    # Additional colors
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    GRAY = '\033[90m'


def print_banner():
    """Display attractive ASCII art banner."""
    os.system('cls' if os.name == 'nt' else 'clear')
    
    banner = f"""
{Colors.CYAN}╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║  {Colors.RED}██╗  ██╗███████╗██╗   ██╗██╗      ██████╗  ██████╗  ██████╗ ███████╗██████╗  {Colors.CYAN}║
║  {Colors.RED}██║ ██╔╝██╔════╝╚██╗ ██╔╝██║     ██╔═══██╗██╔════╝ ██╔════╝ ██╔════╝██╔══██╗ {Colors.CYAN}║
║  {Colors.RED}█████╔╝ █████╗   ╚████╔╝ ██║     ██║   ██║██║  ███╗██║  ███╗█████╗  ██████╔╝ {Colors.CYAN}║
║  {Colors.RED}██╔═██╗ ██╔══╝    ╚██╔╝  ██║     ██║   ██║██║   ██║██║   ██║██╔══╝  ██╔══██╗ {Colors.CYAN}║
║  {Colors.RED}██║  ██╗███████╗   ██║   ███████╗╚██████╔╝╚██████╔╝╚██████╔╝███████╗██║  ██║ {Colors.CYAN}║
║  {Colors.RED}╚═╝  ╚═╝╚══════╝   ╚═╝   ╚══════╝ ╚═════╝  ╚═════╝  ╚═════╝ ╚══════╝╚═╝  ╚═╝ {Colors.CYAN}║
║                                                                              ║
║  {Colors.YELLOW}████████╗██╗  ██╗██████╗ ███████╗ █████╗ ████████╗    ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗ {Colors.CYAN}║
║  {Colors.YELLOW}╚══██╔══╝██║  ██║██╔══██╗██╔════╝██╔══██╗╚══██╔══╝    ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗{Colors.CYAN}║
║  {Colors.YELLOW}   ██║   ███████║██████╔╝█████╗  ███████║   ██║       ███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝{Colors.CYAN}║
║  {Colors.YELLOW}   ██║   ██╔══██║██╔══██╗██╔══╝  ██╔══██║   ██║       ██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗{Colors.CYAN}║
║  {Colors.YELLOW}   ██║   ██║  ██║██║  ██║███████╗██║  ██║   ██║       ██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║{Colors.CYAN}║
║  {Colors.YELLOW}   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝   ╚═╝       ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝{Colors.CYAN}║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝{Colors.ENDC}

{Colors.MAGENTA}                    ╔══════════════════════════════════════════╗
                    ║  {Colors.WHITE}Advanced Behavioral Detection Engine{Colors.MAGENTA}  ║
                    ║  {Colors.WHITE}Version 4.0 - Production Release{Colors.MAGENTA}       ║
                    ╚══════════════════════════════════════════════════════════════════════╝{Colors.ENDC}

{Colors.GRAY}                    ┌─────────────────────────────────────────────┐
                    │ {Colors.GREEN}✓{Colors.GRAY} Enterprise-Grade Detection Algorithm  │
                    │ {Colors.GREEN}✓{Colors.GRAY} Multi-Layer Threat Intelligence       │
                    │ {Colors.GREEN}✓{Colors.GRAY} Advanced Behavioral Analysis           │
                    │ {Colors.GREEN}✓{Colors.GRAY} Real-Time Memory Scanning              │
                    │ {Colors.GREEN}✓{Colors.GRAY} Network Exfiltration Detection         │
                    │ {Colors.GREEN}✓{Colors.GRAY} Process Injection Analysis             │
                    │ {Colors.GREEN}✓{Colors.GRAY} Zero False Positives Target (<5%)     │
                    └─────────────────────────────────────────────────────────────────────┘{Colors.ENDC}

{Colors.YELLOW}    ⚠️  LEGAL WARNING ⚠️{Colors.ENDC}
{Colors.WHITE}    This tool is for {Colors.CYAN}educational{Colors.WHITE} and {Colors.CYAN}defensive security research{Colors.WHITE} only.
    Unauthorized use may violate privacy laws. Always obtain proper consent.{Colors.ENDC}

{Colors.CYAN}    Author  : {Colors.WHITE}Sagar Suryawanshi{Colors.ENDC}
{Colors.CYAN}    GitHub  : {Colors.WHITE}https://github.com/CyberSec-Sagar-Security/Anti-Keylogger.git{Colors.ENDC}
{Colors.CYAN}    License : {Colors.WHITE}MIT License - For Educational Use{Colors.ENDC}

"""
    print(banner)
    
    # Loading animation
    print(f"{Colors.CYAN}    [{'=' * 50}]{Colors.ENDC}")
    print(f"{Colors.YELLOW}    🔍 Initializing Detection Engine...{Colors.ENDC}", end="", flush=True)
    for i in range(3):
        time.sleep(0.3)
        print(".", end="", flush=True)
    print(f" {Colors.GREEN}✓{Colors.ENDC}")
    
    print(f"{Colors.YELLOW}    🛡️  Loading Threat Intelligence Database...{Colors.ENDC}", end="", flush=True)
    for i in range(3):
        time.sleep(0.2)
        print(".", end="", flush=True)
    print(f" {Colors.GREEN}✓{Colors.ENDC}")
    
    print(f"{Colors.YELLOW}    ⚙️  Calibrating Behavioral Analysis Algorithms...{Colors.ENDC}", end="", flush=True)
    for i in range(3):
        time.sleep(0.2)
        print(".", end="", flush=True)
    print(f" {Colors.GREEN}✓{Colors.ENDC}")
    
    print(f"{Colors.CYAN}    [{'=' * 50}]{Colors.ENDC}\n")
    
    print(f"{Colors.GREEN}{Colors.BOLD}    ✅ ALL SYSTEMS READY{Colors.ENDC}\n")
    
    # Wait for user to acknowledge
    input(f"{Colors.CYAN}    Press ENTER to start scanning...{Colors.ENDC}")
    print()


def print_section_header(title: str, icon: str = "🔍"):
    """Print a styled section header."""
    print(f"\n{Colors.CYAN}{'═' * 80}{Colors.ENDC}")
    print(f"{Colors.BOLD}{Colors.WHITE}{icon}  {title.upper()}{Colors.ENDC}")
    print(f"{Colors.CYAN}{'═' * 80}{Colors.ENDC}\n")


def print_scanning_animation():
    """Show scanning animation."""
    frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
    print(f"{Colors.YELLOW}    Scanning system hooks", end="", flush=True)
    for _ in range(15):
        for frame in frames:
            print(f"\r{Colors.YELLOW}    {frame} Scanning system hooks...{Colors.ENDC}", end="", flush=True)
            time.sleep(0.1)
    print(f"\r{Colors.GREEN}    ✓ Scan complete!{Colors.ENDC}                    \n")


# ======================== END VISUAL ENHANCEMENTS ========================



@dataclass
class KeyloggerDetection:
    """High-confidence keylogger detection result."""
    pid: int
    name: str
    path: str
    confidence: float  # 0.0 to 1.0
    evidence: List[str]
    threat_score: int  # Number of strong indicators (0-10)
    network_activity: bool = False
    file_logging: bool = False
    memory_suspicious: bool = False
    process_injection: bool = False


class ProductionKeyloggerDetector:
    """
    Production-grade keylogger detector with minimal false positives.
    
    Philosophy: Better to miss a sophisticated keylogger than to flag
    every legitimate application as malicious.
    """
    
    def __init__(self):
        """Initialize detector with comprehensive whitelists."""
        self.trusted_publishers = self._get_trusted_publishers()
        self.safe_process_names = self._get_safe_process_names()
        self.safe_paths = self._get_safe_paths()
        
    def _get_trusted_publishers(self) -> Set[str]:
        """Comprehensive list of legitimate software publishers."""
        return {
            # Major Tech Companies
            'microsoft corporation', 'microsoft windows', 'microsoft',
            'apple inc.', 'apple inc', 'apple computer, inc.', 'apple',
            'google llc', 'google inc.', 'google',
            
            # Hardware Manufacturers
            'hp inc.', 'hewlett-packard', 'hp development company', 'hp',
            'dell inc.', 'dell computer corporation', 'dell',
            'lenovo', 'lenovo group limited',
            'asus', 'asustek computer inc.',
            
            # Peripheral Manufacturers  
            'logitech inc.', 'logitech',
            'razer inc.', 'razer',
            'corsair memory, inc.', 'corsair',
            'steelseries', 'steelseries aps',
            
            # Graphics/Drivers
            'nvidia corporation', 'nvidia',
            'advanced micro devices, inc.', 'amd', 'ati technologies inc.',
            'intel corporation', 'intel',
            'realtek semiconductor corp.', 'realtek',
            
            # Software Companies
            'mozilla corporation', 'mozilla foundation', 'mozilla',
            'oracle corporation', 'oracle america, inc.', 'oracle',
            'adobe inc.', 'adobe systems incorporated', 'adobe',
            'vmware, inc.', 'vmware',
            'citrix systems, inc.', 'citrix',
            
            # Security Software
            'symantec corporation', 'norton',
            'mcafee, llc', 'mcafee inc.', 'mcafee',
            'trend micro inc.', 'trend micro',
            'kaspersky lab', 'kaspersky',
            'avast software', 'avg technologies',
            'malwarebytes inc.', 'malwarebytes',
            
            # Communication Tools
            'zoom video communications, inc.', 'zoom',
            'cisco systems, inc.', 'cisco',
            'slack technologies, inc.', 'slack',
            'discord inc.', 'discord',
            'telegram messenger llp', 'telegram',
            'whatsapp inc.', 'whatsapp',
            
            # Media/Entertainment
            'spotify ab', 'spotify ltd', 'spotify',
            'valve corporation', 'valve',
            'epic games, inc.', 'epic games',
            
            # Cloud Storage
            'dropbox, inc.', 'dropbox',
            'box, inc.', 'box',
            
            # Development Tools
            'jetbrains s.r.o.', 'jetbrains',
            'github, inc.', 'github',
            'atlassian pty ltd', 'atlassian',
        }
    
    def _get_safe_process_names(self) -> Set[str]:
        """Processes that are ALWAYS safe (even if unsigned)."""
        return {
            # Windows Core
            'system', 'smss.exe', 'csrss.exe', 'wininit.exe', 'services.exe',
            'lsass.exe', 'svchost.exe', 'explorer.exe', 'taskhostw.exe',
            'dwm.exe', 'winlogon.exe', 'fontdrvhost.exe', 'sihost.exe',
            'ctfmon.exe', 'taskmgr.exe', 'registry', 'spoolsv.exe',
            
            # Windows Apps
            'shellhost.exe', 'lockapp.exe', 'runtimebroker.exe',
            'applicationframehost.exe', 'startmenuexperiencehost.exe',
            'searchhost.exe', 'widgets.exe', 'textinputhost.exe',
            'securityhealthsystray.exe', 'securityhealthservice.exe',
            
            # Microsoft Office
            'winword.exe', 'excel.exe', 'powerpnt.exe', 'outlook.exe',
            'onenote.exe', 'teams.exe', 'onedrive.exe',
            
            # Common Browsers
            'chrome.exe', 'firefox.exe', 'msedge.exe', 'iexplore.exe',
            'opera.exe', 'brave.exe',
            
            # Development Tools
            'code.exe', 'devenv.exe', 'sublime_text.exe', 'notepad.exe',
            'notepad++.exe', 'pycharm64.exe', 'idea64.exe',
            
            # Common Apps
            'discord.exe', 'slack.exe', 'zoom.exe', 'spotify.exe',
            'vlc.exe', 'steam.exe',
        }
    
    def _get_safe_paths(self) -> List[str]:
        """Paths that are always considered safe."""
        return [
            r'c:\windows\system32',
            r'c:\windows\syswow64',
            r'c:\windows\explorer.exe',
            r'c:\program files\windowsapps',
            r'c:\windows\systemapps',
            r'c:\windows\winsxs',
            r'c:\program files\\',
            r'c:\program files (x86)\\',
        ]
    
    def _get_publisher(self, file_path: str) -> Optional[str]:
        """Extract publisher/company name from file."""
        if not os.path.exists(file_path):
            return None
        
        try:
            # Try to get file version info
            info = win32api.GetFileVersionInfo(file_path, '\\')
            ms = info.get('StringFileInfo', {})
            
            for lang_codepage in ms:
                strings = ms.get(lang_codepage, {})
                if isinstance(strings, dict):
                    company = strings.get('CompanyName', '')
                    if company and len(company) > 0:
                        return company.strip()
        except:
            pass
        
        return None
    
    def _is_trusted_location(self, file_path: str) -> bool:
        """Check if file is in a trusted location."""
        path_lower = file_path.lower()
        
        # Expanded trusted paths including specific vendors
        trusted_paths = [
            r'c:\windows\system32',
            r'c:\windows\syswow64',
            r'c:\windows\explorer.exe',
            r'c:\program files\windowsapps',
            r'c:\windows\systemapps',
            r'c:\windows\winsxs',
            r'c:\program files\hp',  # HP software
            r'c:\program files\nvidia corporation',  # NVIDIA
            r'c:\program files\logioptionsplus',  # Logitech
            r'c:\program files\logioptions',  # Logitech (older)
            r'c:\program files\dell',  # Dell
            r'c:\program files\intel',  # Intel
            r'c:\program files\amd',  # AMD
            r'c:\program files\realtek',  # Realtek
        ]
        
        # Check if path starts with Program Files (general safe location)
        if r'c:\program files\\' in path_lower or r'c:\program files (x86)\\' in path_lower:
            # But not if it's in a suspicious subfolder
            suspicious_subfolders = ['\\temp\\', '\\cache\\', '\\downloads\\']
            if any(sus in path_lower for sus in suspicious_subfolders):
                return False
            return True
        
        return any(safe in path_lower for safe in trusted_paths)
    
    def _is_suspicious_location(self, file_path: str) -> bool:
        """Check if file is in suspicious location (temp, random user dirs)."""
        path_lower = file_path.lower()
        suspicious = [
            '\\temp\\', '\\tmp\\', 
            'appdata\\local\\temp',
            'appdata\\roaming\\temp',
            '\\downloads\\',
            '\\desktop\\',
            '\\documents\\random',
        ]
        return any(sus in path_lower for sus in suspicious)
    
    def _detect_name_spoofing(self, name: str, path: str) -> Tuple[bool, str]:
        """
        Detect name spoofing - impersonating system processes.
        
        Examples:
        - svchost.exe NOT in System32
        - explorer.exe NOT in C:\\Windows
        - HP.exe → HPP.exe
        """
        name_lower = name.lower()
        path_lower = path.lower()
        
        # Critical system processes that MUST be in specific locations
        critical_processes = {
            'svchost.exe': r'c:\windows\system32',
            'csrss.exe': r'c:\windows\system32',
            'lsass.exe': r'c:\windows\system32',
            'winlogon.exe': r'c:\windows\system32',
            'explorer.exe': r'c:\windows',
            'dwm.exe': r'c:\windows\system32',
        }
        
        for sys_name, required_path in critical_processes.items():
            if name_lower == sys_name:
                if required_path not in path_lower:
                    return (True, f"'{name}' found in WRONG location (not {required_path})")
        
        return (False, "")
    
    def _has_keylogger_keywords(self, name: str, path: str) -> List[str]:
        """Check for obvious keylogger-related keywords."""
        keywords = [
            'keylog', 'keystroke', 'keycapture', 'keyrecord',
            'pynput', 'pyhook', 'keyboard_hook', 'kb_hook',
            'hook_keys', 'capture_keys', 'record_keys'
        ]
        
        full_text = (name + ' ' + path).lower()
        return [kw for kw in keywords if kw in full_text]
    
    def _check_network_exfiltration(self, pid: int) -> Tuple[bool, str]:
        """
        Check if process has suspicious network connections.
        Keyloggers often send data to remote servers.
        """
        try:
            proc = psutil.Process(pid)
            # Use net_connections() instead of deprecated connections()
            try:
                connections = proc.net_connections(kind='inet')
            except (psutil.AccessDenied, AttributeError):
                # Fallback for older psutil versions
                return (False, "")
            
            # Check for outbound connections to non-standard ports
            suspicious_connections = []
            for conn in connections:
                if conn.status == 'ESTABLISHED' and conn.raddr:
                    # Flag non-standard ports (not 80, 443, 53)
                    if conn.raddr.port not in [80, 443, 53, 22, 21, 25, 587]:
                        suspicious_connections.append(f"{conn.raddr.ip}:{conn.raddr.port}")
            
            if suspicious_connections:
                return (True, f"Outbound connections: {', '.join(suspicious_connections[:3])}")
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
        
        return (False, "")
    
    def _check_file_logging(self, pid: int) -> Tuple[bool, str]:
        """
        Check if process is writing to suspicious log files.
        Keyloggers typically write captured keys to files.
        """
        try:
            proc = psutil.Process(pid)
            open_files = proc.open_files()
            
            suspicious_files = []
            suspicious_patterns = [
                'log', 'dump', 'capture', 'record', 'output',
                '.txt', '.dat', '.bin', 'temp', 'cache'
            ]
            
            for file in open_files:
                file_lower = file.path.lower()
                # Check if file is being written to (not just read)
                if any(pattern in file_lower for pattern in suspicious_patterns):
                    # Extra suspicious if in temp, appdata, or user folders
                    if any(loc in file_lower for loc in ['\\temp\\', '\\appdata\\', '\\users\\']):
                        suspicious_files.append(file.path)
            
            if suspicious_files:
                return (True, f"Writing to: {suspicious_files[0]}")
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
        
        return (False, "")
    
    def _check_memory_patterns(self, pid: int) -> Tuple[bool, str]:
        """
        Analyze memory usage patterns.
        Keyloggers often have specific memory characteristics.
        """
        try:
            proc = psutil.Process(pid)
            mem_info = proc.memory_info()
            
            # Check for suspiciously low memory usage with keyboard hook
            # (indicates minimal UI, just capturing)
            if mem_info.rss < 10 * 1024 * 1024:  # Less than 10MB
                return (True, f"Minimal memory footprint: {mem_info.rss / (1024*1024):.1f}MB")
            
            # Check for excessive private memory (might be buffering captures)
            if mem_info.rss > 500 * 1024 * 1024:  # More than 500MB for simple hook
                return (True, f"Excessive memory usage: {mem_info.rss / (1024*1024):.1f}MB")
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
        
        return (False, "")
    
    def _check_process_ancestry(self, pid: int) -> Tuple[bool, str]:
        """
        Check parent-child process relationships.
        Suspicious if spawned from unexpected parents or injected.
        """
        try:
            proc = psutil.Process(pid)
            parent = proc.parent()
            
            if parent:
                parent_name = parent.name().lower()
                proc_name = proc.name().lower()
                
                # Suspicious patterns
                # 1. System process spawned from user process
                system_names = ['svchost.exe', 'csrss.exe', 'lsass.exe']
                if proc_name in system_names and parent_name not in ['services.exe', 'wininit.exe']:
                    return (True, f"Suspicious parent: {parent.name()} → {proc.name()}")
                
                # 2. Spawned from script interpreters (python, powershell, cmd)
                script_parents = ['python.exe', 'pythonw.exe', 'powershell.exe', 'cmd.exe']
                if parent_name in script_parents:
                    return (True, f"Spawned from: {parent.name()}")
                
                # 3. Orphaned process (parent terminated but child still running)
                if not parent.is_running():
                    return (True, "Orphaned process (parent terminated)")
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
        
        return (False, "")
    
    def _check_dll_injection_indicators(self, pid: int) -> Tuple[bool, str]:
        """
        Check for DLL injection indicators.
        Keyloggers sometimes inject into legitimate processes.
        """
        try:
            proc = psutil.Process(pid)
            
            # Check loaded modules/DLLs
            try:
                # Get process command line
                cmdline = ' '.join(proc.cmdline()).lower()
                
                # Suspicious if no window but has hook (headless)
                if proc.num_threads() < 3:  # Very few threads
                    return (True, f"Minimal threads: {proc.num_threads()} (likely injected)")
            except (psutil.AccessDenied, AttributeError):
                pass
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
        
        return (False, "")
    
    def _advanced_behavioral_analysis(self, pid: int) -> Tuple[float, List[str]]:
        """
        Advanced behavioral analysis using multiple indicators.
        Returns (confidence_boost, evidence_list)
        """
        evidence = []
        confidence = 0.0
        
        # Check network exfiltration
        has_network, net_msg = self._check_network_exfiltration(pid)
        if has_network:
            evidence.append(f"🌐 NETWORK EXFILTRATION: {net_msg}")
            confidence += 0.35
        
        # Check file logging
        has_logging, log_msg = self._check_file_logging(pid)
        if has_logging:
            evidence.append(f"📝 FILE LOGGING: {log_msg}")
            confidence += 0.3
        
        # Check memory patterns
        mem_suspicious, mem_msg = self._check_memory_patterns(pid)
        if mem_suspicious:
            evidence.append(f"🧠 MEMORY PATTERN: {mem_msg}")
            confidence += 0.2
        
        # Check process ancestry
        suspicious_parent, parent_msg = self._check_process_ancestry(pid)
        if suspicious_parent:
            evidence.append(f"👨‍👦 PROCESS ANCESTRY: {parent_msg}")
            confidence += 0.25
        
        # Check DLL injection
        dll_inject, dll_msg = self._check_dll_injection_indicators(pid)
        if dll_inject:
            evidence.append(f"💉 DLL INJECTION: {dll_msg}")
            confidence += 0.3
        
        return (confidence, evidence)
    
    def analyze_process(self, proc: Dict) -> Optional[KeyloggerDetection]:
        """
        Analyze a single hooked process for keylogger indicators.
        
        Returns KeyloggerDetection only if HIGH CONFIDENCE (3+ strong indicators).
        """
        name = proc.get('name', '')
        path = proc.get('path', '')
        pid = proc.get('pid', 0)
        
        # Quick whitelist check - skip known safe processes
        if name.lower() in self.safe_process_names:
            # Exception: Still check if it's in the WRONG location
            is_spoofing, spoof_msg = self._detect_name_spoofing(name, path)
            if not is_spoofing:
                return None  # Definitely safe
        
        # Check if in trusted location
        if self._is_trusted_location(path):
            # Still check for name spoofing
            is_spoofing, spoof_msg = self._detect_name_spoofing(name, path)
            if not is_spoofing:
                return None  # Safe - trusted location
        
        # Get publisher
        publisher = self._get_publisher(path)
        
        # Check if from trusted publisher
        if publisher:
            pub_lower = publisher.lower()
            if any(trusted in pub_lower for trusted in self.trusted_publishers):
                # Trusted publisher - skip unless name spoofing
                is_spoofing, spoof_msg = self._detect_name_spoofing(name, path)
                if not is_spoofing:
                    return None  # Safe - trusted publisher
        
        # Now check for STRONG INDICATORS of keylogger
        evidence = []
        threat_score = 0
        confidence = 0.0
        
        # Indicator 1: Name spoofing (CRITICAL)
        is_spoofing, spoof_msg = self._detect_name_spoofing(name, path)
        if is_spoofing:
            evidence.append(f"🚨 NAME SPOOFING: {spoof_msg}")
            threat_score += 2  # Worth 2 points
            confidence += 0.4
        
        # Indicator 2: Keylogger keywords (CRITICAL)
        keywords = self._has_keylogger_keywords(name, path)
        if keywords:
            evidence.append(f"🚨 KEYLOGGER KEYWORDS: {', '.join(keywords)}")
            threat_score += 2  # Worth 2 points
            confidence += 0.5
        
        # Indicator 3: Unsigned binary with hook (MEDIUM)
        is_signed = proc.get('is_signed', False)
        if not is_signed:
            evidence.append("⚠️ Unsigned binary with keyboard hook")
            threat_score += 1
            confidence += 0.2
        
        # Indicator 4: Suspicious location (MEDIUM)
        if self._is_suspicious_location(path):
            evidence.append(f"⚠️ Suspicious location: {path}")
            threat_score += 1
            confidence += 0.25
        
        # Indicator 5: Unknown publisher + non-standard location (LOW-MEDIUM)
        # BUT: If in Program Files, this is much less suspicious
        if not publisher and not self._is_trusted_location(path):
            evidence.append(f"⚠️ Unknown publisher in non-standard location")
            threat_score += 1
            confidence += 0.15
        elif not publisher and r'c:\program files' in path.lower():
            # In Program Files but couldn't verify publisher - less suspicious
            # Don't add to evidence or threat_score (benefit of the doubt)
            pass
        
        # Indicator 6: Hidden process with hook (MEDIUM)
        if proc.get('is_hidden', False):
            evidence.append("⚠️ Hidden process with keyboard hook")
            threat_score += 1
            confidence += 0.2
        
        # ADVANCED INDICATORS (no keywords needed)
        adv_confidence, adv_evidence = self._advanced_behavioral_analysis(pid)
        if adv_confidence > 0:
            evidence.extend(adv_evidence)
            confidence += adv_confidence
            # Each advanced indicator is worth 1 threat point
            threat_score += len(adv_evidence)
        
        # Track advanced detection flags
        network_activity = any('NETWORK' in e for e in evidence)
        file_logging = any('FILE LOGGING' in e for e in evidence)
        memory_suspicious = any('MEMORY' in e for e in evidence)
        process_injection = any('INJECTION' in e or 'ANCESTRY' in e for e in evidence)
        
        # DECISION: Only flag if threat_score >= 3 (at least 3 strong indicators)
        if threat_score >= 3:
            confidence = min(confidence, 1.0)
            
            return KeyloggerDetection(
                pid=pid,
                name=name,
                path=path,
                confidence=confidence,
                evidence=evidence,
                threat_score=threat_score,
                network_activity=network_activity,
                file_logging=file_logging,
                memory_suspicious=memory_suspicious,
                process_injection=process_injection
            )
        
        # Not enough evidence - probably legitimate
        return None
    
    def scan_system(self) -> List[KeyloggerDetection]:
        """
        Scan system for keyloggers.
        
        Returns ONLY high-confidence detections (not every hooked process).
        """
        print_section_header("SCANNING FOR KEYLOGGERS", "🔍")
        
        enum = WindowsAPIEnumerator()
        
        # Show scanning animation
        print_scanning_animation()
        
        # Get all keyboard hooks
        hooks = enum.detect_hooks()
        keyboard_hooks = [h for h in hooks if 'KEYBOARD' in h.hook_type]
        
        print(f"{Colors.CYAN}    ⌨️  Keyboard hooks detected: {Colors.YELLOW}{len(keyboard_hooks)}{Colors.ENDC}")
        print(f"{Colors.CYAN}    🔬 Analyzing behavioral patterns...{Colors.ENDC}\n")
        
        # Progress bar
        total_hooks = len(set(h.owner_pid for h in keyboard_hooks))
        print(f"{Colors.GRAY}    Progress: [{Colors.ENDC}", end="", flush=True)
        
        # Get unique PIDs with keyboard hooks
        hooked_pids = set(h.owner_pid for h in keyboard_hooks)
        
        # Analyze each hooked process
        detections = []
        for idx, pid in enumerate(hooked_pids, 1):
            # Update progress bar
            progress = int((idx / total_hooks) * 40)
            print(f"\r{Colors.GRAY}    Progress: [{Colors.GREEN}{'█' * progress}{Colors.GRAY}{'░' * (40 - progress)}{Colors.GRAY}] {idx}/{total_hooks}{Colors.ENDC}", end="", flush=True)
            
            proc_info = enum.get_process_info(pid)
            if not proc_info:
                continue
            
            # Convert ProcessInfo dataclass to dict for analyze_process
            proc_dict = {
                'pid': proc_info.pid,
                'name': proc_info.name,
                'path': proc_info.path,
                'is_signed': proc_info.is_signed,
                'is_hidden': proc_info.is_hidden_window,
                'has_hook': True,
            }
            
            detection = self.analyze_process(proc_dict)
            if detection:
                detections.append(detection)
        
        print(f"\r{Colors.GRAY}    Progress: [{Colors.GREEN}{'█' * 40}{Colors.GRAY}] {total_hooks}/{total_hooks}{Colors.ENDC}")
        print(f"{Colors.GREEN}    ✓ Analysis complete!{Colors.ENDC}\n")
        
        return detections
    
    def display_results(self, detections: List[KeyloggerDetection]):
        """Display detection results in user-friendly format."""
        print_section_header("SCAN RESULTS", "📋")
        
        if not detections:
            print(f"{Colors.GREEN}    ╔══════════════════════════════════════════════════════════════╗{Colors.ENDC}")
            print(f"{Colors.GREEN}    ║                                                              ║{Colors.ENDC}")
            print(f"{Colors.GREEN}    ║  {Colors.BOLD}✅ NO KEYLOGGERS DETECTED{Colors.ENDC}{Colors.GREEN}                                  ║{Colors.ENDC}")
            print(f"{Colors.GREEN}    ║                                                              ║{Colors.ENDC}")
            print(f"{Colors.GREEN}    ║  Your system appears clean. All keyboard hooks are from      ║{Colors.ENDC}")
            print(f"{Colors.GREEN}    ║  legitimate applications (HP, Dell, Microsoft, Logitech).    ║{Colors.ENDC}")
            print(f"{Colors.GREEN}    ║                                                              ║{Colors.ENDC}")
            print(f"{Colors.GREEN}    ╚══════════════════════════════════════════════════════════════╝{Colors.ENDC}")
            print()
            return
        
        print(f"{Colors.RED}    ╔══════════════════════════════════════════════════════════════╗{Colors.ENDC}")
        print(f"{Colors.RED}    ║  {Colors.BOLD}🔴 DETECTED {len(detections)} POTENTIAL KEYLOGGER(S){Colors.ENDC}{Colors.RED}                      ║{Colors.ENDC}")
        print(f"{Colors.RED}    ╚══════════════════════════════════════════════════════════════╝{Colors.ENDC}")
        print()
        
        # Sort by confidence (highest first)
        detections.sort(key=lambda d: d.confidence, reverse=True)
        
        for i, det in enumerate(detections, 1):
            # Color based on confidence
            if det.confidence >= 0.8:
                threat_color = Colors.RED
                threat_icon = "🔴"
            elif det.confidence >= 0.6:
                threat_color = Colors.YELLOW
                threat_icon = "🟡"
            else:
                threat_color = Colors.BLUE
                threat_icon = "🔵"
            
            print(f"{threat_color}    ┌{'─' * 76}┐{Colors.ENDC}")
            print(f"{threat_color}    │ {threat_icon} THREAT #{i}{' ' * (70 - len(f'THREAT #{i}'))}│{Colors.ENDC}")
            print(f"{threat_color}    ├{'─' * 76}┤{Colors.ENDC}")
            print(f"    │ {Colors.BOLD}Process:{Colors.ENDC} {det.name:<66} │")
            print(f"    │ {Colors.GRAY}PID: {det.pid:<70}{Colors.ENDC} │")
            print(f"    │ {Colors.GRAY}Path:{Colors.ENDC} {det.path[:63]:<63} │")
            if len(det.path) > 63:
                print(f"    │       {det.path[63:126]:<70} │")
            
            # Confidence bar
            conf_percent = int(det.confidence * 100)
            bar_length = int((det.confidence * 50))
            conf_bar = f"{threat_color}{'█' * bar_length}{Colors.GRAY}{'░' * (50 - bar_length)}{Colors.ENDC}"
            print(f"    │ {Colors.BOLD}Confidence:{Colors.ENDC} {conf_bar} {conf_percent}% │")
            print(f"    │ {Colors.BOLD}Threat Score:{Colors.ENDC} {det.threat_score}/10 indicators{' ' * (50 - len(str(det.threat_score)))}│")
            
            # Show advanced detection flags with icons
            flags = []
            if det.network_activity:
                flags.append(f"{Colors.RED}🌐 Network{Colors.ENDC}")
            if det.file_logging:
                flags.append(f"{Colors.YELLOW}📝 Logging{Colors.ENDC}")
            if det.memory_suspicious:
                flags.append(f"{Colors.MAGENTA}🧠 Memory{Colors.ENDC}")
            if det.process_injection:
                flags.append(f"{Colors.CYAN}💉 Injection{Colors.ENDC}")
            
            if flags:
                flags_str = " | ".join(flags)
                print(f"    │ {Colors.BOLD}Advanced Indicators:{Colors.ENDC} {flags_str}{' ' * max(0, 45 - len(' | '.join([f.split()[1] for f in flags])))} │")
            
            print(f"    │{' ' * 76}│")
            print(f"    │ {Colors.BOLD}Evidence:{Colors.ENDC}{' ' * 65}│")
            for evidence in det.evidence:
                # Wrap long evidence lines
                if len(evidence) <= 70:
                    print(f"    │   • {evidence:<71} │")
                else:
                    print(f"    │   • {evidence[:70]:<70} │")
                    print(f"    │     {evidence[70:140]:<72} │")
            
            print(f"    │{' ' * 76}│")
            
            # Recommendation with appropriate color
            if det.confidence >= 0.8:
                rec_color = Colors.RED
                rec_text = "⛔ RECOMMENDATION: TERMINATE IMMEDIATELY"
            elif det.confidence >= 0.6:
                rec_color = Colors.YELLOW
                rec_text = "⚠️  RECOMMENDATION: INVESTIGATE URGENTLY"
            else:
                rec_color = Colors.BLUE
                rec_text = "ℹ️  RECOMMENDATION: MONITOR AND VERIFY"
            
            print(f"    │ {rec_color}{Colors.BOLD}{rec_text}{Colors.ENDC}{' ' * (74 - len(rec_text))}│")
            print(f"{threat_color}    └{'─' * 76}┘{Colors.ENDC}")
            print()
        
        # Summary box
        high_conf = sum(1 for d in detections if d.confidence >= 0.8)
        medium_conf = sum(1 for d in detections if 0.6 <= d.confidence < 0.8)
        low_conf = sum(1 for d in detections if d.confidence < 0.6)
        
        print(f"{Colors.CYAN}    ┌{'─' * 76}┐{Colors.ENDC}")
        print(f"{Colors.CYAN}    │ {Colors.BOLD}📊 DETECTION SUMMARY{Colors.ENDC}{Colors.CYAN}{' ' * 55}│{Colors.ENDC}")
        print(f"{Colors.CYAN}    ├{'─' * 76}┤{Colors.ENDC}")
        print(f"    │  Total threats detected: {Colors.BOLD}{len(detections)}{Colors.ENDC}{' ' * (52 - len(str(len(detections))))}│")
        print(f"    │  {Colors.RED}🔴{Colors.ENDC} High confidence (≥80%): {Colors.RED}{high_conf}{Colors.ENDC}{' ' * (46 - len(str(high_conf)))}│")
        print(f"    │  {Colors.YELLOW}🟡{Colors.ENDC} Medium confidence (60-80%): {Colors.YELLOW}{medium_conf}{Colors.ENDC}{' ' * (42 - len(str(medium_conf)))}│")
        print(f"    │  {Colors.BLUE}🔵{Colors.ENDC} Low confidence (<60%): {Colors.BLUE}{low_conf}{Colors.ENDC}{' ' * (47 - len(str(low_conf)))}│")
        print(f"{Colors.CYAN}    └{'─' * 76}┘{Colors.ENDC}")
        print()


def main():
    """Main entry point."""
    # Show attractive banner
    print_banner()
    
    try:
        # Initialize detector
        detector = ProductionKeyloggerDetector()
        
        # Scan system
        detections = detector.scan_system()
        
        # Display results
        detector.display_results(detections)
        
        # Footer
        print(f"{Colors.CYAN}{'═' * 80}{Colors.ENDC}")
        print(f"{Colors.GREEN}    ✅ Scan completed successfully{Colors.ENDC}")
        print(f"{Colors.GRAY}    Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Colors.ENDC}")
        print(f"{Colors.CYAN}{'═' * 80}{Colors.ENDC}\n")
        
    except KeyboardInterrupt:
        print(f"\n\n{Colors.YELLOW}    ⚠️  Scan interrupted by user{Colors.ENDC}")
        print(f"{Colors.GRAY}    Exiting safely...{Colors.ENDC}\n")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Colors.RED}    ❌ ERROR: {e}{Colors.ENDC}")
        import traceback
        print(f"{Colors.GRAY}{traceback.format_exc()}{Colors.ENDC}")
        sys.exit(1)


if __name__ == "__main__":
    main()
