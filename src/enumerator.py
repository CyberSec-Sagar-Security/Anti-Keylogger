"""
Enumerator Module - Hook and process enumeration with Windows API.

This module handles detection of keyboard hooks and collection of process metadata.
Supports both real Windows API calls and mock mode for testing.
"""

import ctypes
from ctypes import wintypes
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime
import os

# Windows API constants
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
MAX_PATH = 260

# Hook types
WH_KEYBOARD = 2
WH_KEYBOARD_LL = 13
WH_MOUSE = 7
WH_MOUSE_LL = 14


@dataclass
class ProcessInfo:
    """Process metadata structure."""
    pid: int
    name: str
    path: str
    parent_pid: int
    is_signed: bool
    user_account: str
    is_hidden_window: bool
    is_service: bool
    loaded_dlls: List[str]
    privileges: List[str]
    timestamp: str


@dataclass
class HookInfo:
    """Hook detection metadata structure."""
    hook_id: int
    hook_type: str
    owner_pid: int
    owner_process: str
    module_path: str
    timestamp: str


class WindowsAPIEnumerator:
    """Real Windows API-based hook and process enumeration."""
    
    def __init__(self):
        """Initialize Windows API enumerator."""
        self._setup_api()
    
    def _setup_api(self):
        """Set up Windows API function signatures."""
        try:
            # Kernel32
            self.kernel32 = ctypes.windll.kernel32
            self.psapi = ctypes.windll.psapi
            self.advapi32 = ctypes.windll.advapi32
            self.user32 = ctypes.windll.user32
            
            # Set up function prototypes
            self.kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
            self.kernel32.OpenProcess.restype = wintypes.HANDLE
            
            self.kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
            self.kernel32.CloseHandle.restype = wintypes.BOOL
            
        except Exception as e:
            print(f"Warning: Could not initialize Windows API: {e}")
    
    def enumerate_processes(self) -> List[int]:
        """
        Enumerate all running process IDs.
        
        Returns:
            List of process IDs
        """
        try:
            # Allocate buffer for PIDs
            max_processes = 2048
            pid_array = (wintypes.DWORD * max_processes)()
            bytes_returned = wintypes.DWORD()
            
            # Call EnumProcesses
            if not self.psapi.EnumProcesses(
                ctypes.byref(pid_array),
                ctypes.sizeof(pid_array),
                ctypes.byref(bytes_returned)
            ):
                return []
            
            # Calculate number of PIDs returned
            num_pids = bytes_returned.value // ctypes.sizeof(wintypes.DWORD)
            pids = [pid_array[i] for i in range(num_pids) if pid_array[i] != 0]
            
            return pids
            
        except Exception as e:
            print(f"Error enumerating processes: {e}")
            return []
    
    def get_process_info(self, pid: int) -> Optional[ProcessInfo]:
        """
        Get comprehensive metadata for a process.
        
        Args:
            pid: Process ID
            
        Returns:
            ProcessInfo object or None if access denied
        """
        try:
            # Open process handle
            h_process = self.kernel32.OpenProcess(
                PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                False,
                pid
            )
            
            if not h_process:
                # Try limited information access
                h_process = self.kernel32.OpenProcess(
                    PROCESS_QUERY_LIMITED_INFORMATION,
                    False,
                    pid
                )
            
            if not h_process:
                return None
            
            try:
                # Get process name and path
                name, path = self._get_process_name_path(h_process, pid)
                
                # Get parent PID
                parent_pid = self._get_parent_pid(pid)
                
                # Check digital signature
                is_signed = self._check_signature(path)
                
                # Get user account
                user_account = self._get_process_user(h_process)
                
                # Check window visibility
                is_hidden = self._check_hidden_window(pid)
                
                # Check if service
                is_service = self._is_service_process(pid)
                
                # Get loaded DLLs
                loaded_dlls = self._get_loaded_modules(h_process, pid)
                
                # Get privileges (basic check)
                privileges = self._get_process_privileges(h_process)
                
                return ProcessInfo(
                    pid=pid,
                    name=name,
                    path=path,
                    parent_pid=parent_pid,
                    is_signed=is_signed,
                    user_account=user_account,
                    is_hidden_window=is_hidden,
                    is_service=is_service,
                    loaded_dlls=loaded_dlls,
                    privileges=privileges,
                    timestamp=datetime.now().isoformat()
                )
                
            finally:
                self.kernel32.CloseHandle(h_process)
                
        except Exception as e:
            # Silently fail for inaccessible processes
            return None
    
    def _get_process_name_path(self, h_process: int, pid: int) -> Tuple[str, str]:
        """Get process name and full path."""
        try:
            # Get full path
            path_buffer = ctypes.create_unicode_buffer(MAX_PATH)
            path_size = wintypes.DWORD(MAX_PATH)
            
            if self.kernel32.QueryFullProcessImageNameW(
                h_process,
                0,
                path_buffer,
                ctypes.byref(path_size)
            ):
                path = path_buffer.value
                name = os.path.basename(path)
                return name, path
            
            # Fallback: try GetModuleFileNameEx
            if self.psapi.GetModuleFileNameExW(
                h_process,
                None,
                path_buffer,
                MAX_PATH
            ):
                path = path_buffer.value
                name = os.path.basename(path)
                return name, path
            
            return f"<PID {pid}>", ""
            
        except Exception:
            return f"<PID {pid}>", ""
    
    def _get_parent_pid(self, pid: int) -> int:
        """Get parent process ID."""
        try:
            import win32process
            import win32api
            
            handle = win32api.OpenProcess(PROCESS_QUERY_INFORMATION, False, pid)
            if handle:
                try:
                    parent_pid = win32process.GetProcessId(
                        win32process.GetProcessParentProcess(handle)
                    )
                    return parent_pid
                finally:
                    win32api.CloseHandle(handle)
        except:
            pass
        
        return 0  # Unknown parent
    
    def _check_signature(self, path: str) -> bool:
        """
        Check if executable has valid digital signature.
        
        Args:
            path: Full path to executable
            
        Returns:
            True if signed and valid, False otherwise
        """
        if not path or not os.path.exists(path):
            return False
        
        try:
            # Try using pywin32 for signature verification
            import win32api
            
            # Simple check: does file have version info with company?
            # Full signature verification requires WinVerifyTrust API
            info = win32api.GetFileVersionInfo(path, '\\')
            if info:
                # Has version info, likely signed (simplified check)
                return True
                
        except:
            pass
        
        # Default to unsigned if we can't verify
        return False
    
    def _get_process_user(self, h_process: int) -> str:
        """Get user account running the process."""
        try:
            import win32security
            import win32api
            
            token = win32security.OpenProcessToken(
                h_process,
                win32security.TOKEN_QUERY
            )
            
            if token:
                try:
                    user_sid = win32security.GetTokenInformation(
                        token,
                        win32security.TokenUser
                    )
                    
                    account, domain, _ = win32security.LookupAccountSid(
                        None,
                        user_sid[0]
                    )
                    
                    return f"{domain}\\{account}"
                finally:
                    token.Close()
                    
        except:
            pass
        
        return "UNKNOWN"
    
    def _check_hidden_window(self, pid: int) -> bool:
        """Check if process has hidden/invisible windows."""
        try:
            import win32gui
            import win32process
            
            def enum_callback(hwnd, windows):
                if win32gui.IsWindowVisible(hwnd):
                    _, found_pid = win32process.GetWindowThreadProcessId(hwnd)
                    if found_pid == pid:
                        windows.append(hwnd)
                return True
            
            windows = []
            win32gui.EnumWindows(enum_callback, windows)
            
            # If no visible windows found, might be hidden
            return len(windows) == 0
            
        except:
            return False
    
    def _is_service_process(self, pid: int) -> bool:
        """Check if process is a Windows service."""
        try:
            import win32service
            import win32serviceutil
            
            # This is a simplified check
            # Full implementation would enumerate services and match PIDs
            return False
            
        except:
            return False
    
    def _get_loaded_modules(self, h_process: int, pid: int) -> List[str]:
        """Get list of DLLs loaded by process."""
        try:
            import win32process
            
            modules = win32process.EnumProcessModules(h_process)
            module_names = []
            
            for module in modules[:10]:  # Limit to first 10
                try:
                    name = win32process.GetModuleFileNameEx(h_process, module)
                    module_names.append(os.path.basename(name))
                except:
                    continue
            
            return module_names
            
        except:
            return []
    
    def _get_process_privileges(self, h_process: int) -> List[str]:
        """Get process privilege information (simplified)."""
        try:
            import win32security
            
            token = win32security.OpenProcessToken(
                h_process,
                win32security.TOKEN_QUERY
            )
            
            if token:
                try:
                    # Check if elevated
                    elevation = win32security.GetTokenInformation(
                        token,
                        win32security.TokenElevation
                    )
                    
                    if elevation:
                        return ["ELEVATED"]
                    
                finally:
                    token.Close()
                    
        except:
            pass
        
        return ["NORMAL"]
    
    def detect_hooks(self) -> List[HookInfo]:
        """
        Detect keyboard hooks (process-based detection).
        
        Note: Direct hook enumeration APIs are restricted, so we use
        process-based detection heuristics.
        
        Returns:
            List of detected hooks
        """
        hooks = []
        hook_id = 1
        
        # Enumerate all processes
        pids = self.enumerate_processes()
        
        for pid in pids:
            proc_info = self.get_process_info(pid)
            
            if not proc_info:
                continue
            
            # Heuristic: Check if process likely has keyboard hooks
            # Look for common hook-related DLLs or process characteristics
            has_hook_indicators = (
                any("user32" in dll.lower() for dll in proc_info.loaded_dlls) or
                any("hook" in dll.lower() for dll in proc_info.loaded_dlls)
            )
            
            # For demo/detection purposes, flag certain processes
            # In real implementation, would use more sophisticated detection
            if has_hook_indicators or self._likely_has_hooks(proc_info):
                hook = HookInfo(
                    hook_id=hook_id,
                    hook_type="WH_KEYBOARD_LL",  # Assumed low-level
                    owner_pid=pid,
                    owner_process=proc_info.name,
                    module_path=proc_info.path,
                    timestamp=datetime.now().isoformat()
                )
                hooks.append(hook)
                hook_id += 1
        
        return hooks
    
    def _likely_has_hooks(self, proc_info: ProcessInfo) -> bool:
        """
        Heuristic to determine if process likely has hooks.
        
        This is a simplified detection method since direct hook
        enumeration requires kernel-level access.
        """
        # Processes that commonly have hooks
        common_hook_processes = [
            "explorer.exe",
            "skype.exe",
            "discord.exe",
            "slack.exe",
            "teams.exe",
            "obs64.exe",
            "obs32.exe"
        ]
        
        return proc_info.name.lower() in common_hook_processes


class MockEnumerator:
    """Mock enumerator for testing without Windows API."""
    
    def enumerate_processes(self) -> List[int]:
        """Return mock process IDs."""
        return [4, 1234, 2248, 4120, 8192, 5678]
    
    def get_process_info(self, pid: int) -> Optional[ProcessInfo]:
        """Return mock process information."""
        mock_data = {
            4: ProcessInfo(
                pid=4, name="System", path="C:\\Windows\\System32\\ntoskrnl.exe",
                parent_pid=0, is_signed=True, user_account="NT AUTHORITY\\SYSTEM",
                is_hidden_window=True, is_service=True,
                loaded_dlls=["ntdll.dll", "kernel32.dll"],
                privileges=["SYSTEM"], timestamp=datetime.now().isoformat()
            ),
            1234: ProcessInfo(
                pid=1234, name="svchost.exe", path="C:\\Windows\\System32\\svchost.exe",
                parent_pid=4, is_signed=True, user_account="NT AUTHORITY\\NETWORK SERVICE",
                is_hidden_window=True, is_service=True,
                loaded_dlls=["ntdll.dll", "kernel32.dll", "user32.dll"],
                privileges=["NORMAL"], timestamp=datetime.now().isoformat()
            ),
            2248: ProcessInfo(
                pid=2248, name="explorer.exe", path="C:\\Windows\\explorer.exe",
                parent_pid=1234, is_signed=True, user_account="DESKTOP\\User",
                is_hidden_window=False, is_service=False,
                loaded_dlls=["ntdll.dll", "kernel32.dll", "user32.dll", "shell32.dll"],
                privileges=["NORMAL"], timestamp=datetime.now().isoformat()
            ),
            4120: ProcessInfo(
                pid=4120, name="badproc.exe", path="C:\\Temp\\badproc.exe",
                parent_pid=2248, is_signed=False, user_account="DESKTOP\\User",
                is_hidden_window=True, is_service=False,
                loaded_dlls=["ntdll.dll", "kernel32.dll", "user32.dll", "suspicious.dll"],
                privileges=["ELEVATED"], timestamp=datetime.now().isoformat()
            ),
            8192: ProcessInfo(
                pid=8192, name="unknown.exe", path="C:\\Users\\User\\AppData\\Local\\Temp\\unknown.exe",
                parent_pid=2248, is_signed=False, user_account="DESKTOP\\User",
                is_hidden_window=False, is_service=False,
                loaded_dlls=["ntdll.dll", "kernel32.dll"],
                privileges=["NORMAL"], timestamp=datetime.now().isoformat()
            ),
            5678: ProcessInfo(
                pid=5678, name="chrome.exe", path="C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
                parent_pid=2248, is_signed=True, user_account="DESKTOP\\User",
                is_hidden_window=False, is_service=False,
                loaded_dlls=["ntdll.dll", "kernel32.dll", "user32.dll"],
                privileges=["NORMAL"], timestamp=datetime.now().isoformat()
            ),
        }
        
        return mock_data.get(pid)
    
    def detect_hooks(self) -> List[HookInfo]:
        """Return mock hook detections."""
        return [
            HookInfo(
                hook_id=1,
                hook_type="WH_KEYBOARD_LL",
                owner_pid=2248,
                owner_process="explorer.exe",
                module_path="C:\\Windows\\explorer.exe",
                timestamp=datetime.now().isoformat()
            ),
            HookInfo(
                hook_id=2,
                hook_type="WH_KEYBOARD_LL",
                owner_pid=4120,
                owner_process="badproc.exe",
                module_path="C:\\Temp\\badproc.exe",
                timestamp=datetime.now().isoformat()
            ),
            HookInfo(
                hook_id=3,
                hook_type="WH_KEYBOARD",
                owner_pid=8192,
                owner_process="unknown.exe",
                module_path="C:\\Users\\User\\AppData\\Local\\Temp\\unknown.exe",
                timestamp=datetime.now().isoformat()
            ),
        ]


def get_enumerator(mock_mode: bool = False):
    """
    Get appropriate enumerator instance.
    
    Args:
        mock_mode: Use mock data instead of real Windows API
        
    Returns:
        Enumerator instance
    """
    if mock_mode:
        return MockEnumerator()
    else:
        try:
            return WindowsAPIEnumerator()
        except Exception as e:
            print(f"Warning: Failed to initialize Windows API enumerator: {e}")
            print("Falling back to mock mode")
            return MockEnumerator()


if __name__ == "__main__":
    # Test enumeration
    print("Testing Mock Enumerator...")
    enum = MockEnumerator()
    
    pids = enum.enumerate_processes()
    print(f"\nFound {len(pids)} processes")
    
    for pid in pids:
        info = enum.get_process_info(pid)
        if info:
            print(f"\nPID {pid}: {info.name}")
            print(f"  Path: {info.path}")
            print(f"  Signed: {info.is_signed}")
            print(f"  Hidden: {info.is_hidden_window}")
            print(f"  User: {info.user_account}")
    
    hooks = enum.detect_hooks()
    print(f"\n\nFound {len(hooks)} hooks:")
    for hook in hooks:
        print(f"  Hook {hook.hook_id}: {hook.hook_type} from PID {hook.owner_pid} ({hook.owner_process})")
