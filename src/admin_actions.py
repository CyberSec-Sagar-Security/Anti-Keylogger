"""
Admin Actions Module - Process termination and quarantine with explicit consent.

This module provides administrative actions for dealing with suspicious processes.
ALL actions require explicit user confirmation and administrator privileges.
"""

import ctypes
from typing import Optional, Tuple
import os

from enumerator import ProcessInfo
from ui import UI


class AdminActions:
    """
    Administrative actions for process management.
    
    REQUIRES: Administrator privileges
    REQUIRES: Explicit user confirmation for all actions
    """
    
    def __init__(self, ui: Optional[UI] = None):
        """
        Initialize admin actions manager.
        
        Args:
            ui: UI instance for user interaction
        """
        self.ui = ui or UI()
        self.is_admin = self._check_admin_privileges()
        
        if not self.is_admin:
            self.ui.print_warning(
                "Admin actions require elevated privileges. "
                "Run as Administrator for full functionality."
            )
    
    def _check_admin_privileges(self) -> bool:
        """
        Check if running with administrator privileges.
        
        Returns:
            True if running as admin, False otherwise
        """
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
    
    def terminate_process(self, proc_info: ProcessInfo, force: bool = False) -> bool:
        """
        Terminate a process after confirmation.
        
        Args:
            proc_info: Process to terminate
            force: Force termination without graceful shutdown
            
        Returns:
            True if terminated, False if cancelled or failed
        """
        if not self.is_admin:
            self.ui.print_error("Administrator privileges required to terminate processes")
            return False
        
        # Display process information
        self.ui.print_separator()
        self.ui.print_warning("PROCESS TERMINATION REQUEST")
        self.ui.print_info(f"PID: {proc_info.pid}")
        self.ui.print_info(f"Name: {proc_info.name}")
        self.ui.print_info(f"Path: {proc_info.path}")
        self.ui.print_info(f"User: {proc_info.user_account}")
        self.ui.print_separator()
        
        # Warning message
        self.ui.print_warning(
            "⚠️  WARNING: Terminating processes can cause data loss or system instability!"
        )
        self.ui.print_warning(
            "    - Ensure you have saved all work in this process"
        )
        self.ui.print_warning(
            "    - System processes should NOT be terminated"
        )
        self.ui.print_warning(
            "    - This action cannot be undone"
        )
        print()
        
        # Require explicit confirmation
        confirmation = self.ui.prompt_input(
            f"Type the process name '{proc_info.name}' to confirm termination",
            default=""
        )
        
        if confirmation != proc_info.name:
            self.ui.print_info("Termination cancelled (name mismatch)")
            return False
        
        # Final yes/no confirmation
        final_confirm = self.ui.prompt_yes_no(
            "Are you ABSOLUTELY SURE you want to terminate this process?",
            default=False
        )
        
        if not final_confirm:
            self.ui.print_info("Termination cancelled by user")
            return False
        
        # Attempt termination
        try:
            success, message = self._kill_process(proc_info.pid, force)
            
            if success:
                self.ui.print_success(f"Process {proc_info.name} (PID {proc_info.pid}) terminated")
                return True
            else:
                self.ui.print_error(f"Failed to terminate process: {message}")
                return False
                
        except Exception as e:
            self.ui.print_error(f"Error terminating process: {e}")
            return False
    
    def _kill_process(self, pid: int, force: bool = False) -> Tuple[bool, str]:
        """
        Kill a process by PID.
        
        Args:
            pid: Process ID
            force: Force kill (TerminateProcess) vs graceful
            
        Returns:
            Tuple of (success, message)
        """
        try:
            import win32api
            import win32process
            import win32con
            
            # Open process handle
            handle = win32api.OpenProcess(
                win32con.PROCESS_TERMINATE | win32con.PROCESS_QUERY_INFORMATION,
                False,
                pid
            )
            
            if not handle:
                return False, "Failed to open process handle"
            
            try:
                if force:
                    # Force terminate
                    win32process.TerminateProcess(handle, 1)
                else:
                    # Try graceful exit first
                    try:
                        win32api.PostThreadMessage(
                            win32process.GetWindowThreadProcessId(handle)[0],
                            win32con.WM_QUIT,
                            0, 0
                        )
                        
                        # Wait briefly, then force if still running
                        import time
                        time.sleep(2)
                        
                        # Check if still running
                        exit_code = win32process.GetExitCodeProcess(handle)
                        if exit_code == win32con.STILL_ACTIVE:
                            win32process.TerminateProcess(handle, 1)
                    except:
                        # Fallback to force terminate
                        win32process.TerminateProcess(handle, 1)
                
                return True, "Process terminated successfully"
                
            finally:
                win32api.CloseHandle(handle)
                
        except Exception as e:
            return False, str(e)
    
    def suspend_process(self, proc_info: ProcessInfo) -> bool:
        """
        Suspend a process (freeze execution) after confirmation.
        
        Args:
            proc_info: Process to suspend
            
        Returns:
            True if suspended, False otherwise
        """
        if not self.is_admin:
            self.ui.print_error("Administrator privileges required")
            return False
        
        self.ui.print_warning(f"Suspending process: {proc_info.name} (PID {proc_info.pid})")
        
        confirm = self.ui.prompt_yes_no(
            "Suspend this process? (Can be resumed later)",
            default=False
        )
        
        if not confirm:
            self.ui.print_info("Suspension cancelled")
            return False
        
        try:
            success, message = self._suspend_process_impl(proc_info.pid)
            
            if success:
                self.ui.print_success(f"Process suspended: {proc_info.name}")
                return True
            else:
                self.ui.print_error(f"Failed to suspend: {message}")
                return False
                
        except Exception as e:
            self.ui.print_error(f"Error suspending process: {e}")
            return False
    
    def _suspend_process_impl(self, pid: int) -> Tuple[bool, str]:
        """
        Suspend process implementation.
        
        Args:
            pid: Process ID
            
        Returns:
            Tuple of (success, message)
        """
        try:
            import win32process
            import win32api
            import win32con
            
            # This requires NtSuspendProcess which is not in pywin32
            # Using ctypes to call directly
            ntdll = ctypes.windll.ntdll
            
            handle = win32api.OpenProcess(
                win32con.PROCESS_SUSPEND_RESUME,
                False,
                pid
            )
            
            if not handle:
                return False, "Failed to open process"
            
            try:
                result = ntdll.NtSuspendProcess(int(handle))
                
                if result == 0:
                    return True, "Process suspended"
                else:
                    return False, f"NtSuspendProcess returned {result}"
                    
            finally:
                win32api.CloseHandle(handle)
                
        except Exception as e:
            return False, str(e)
    
    def quarantine_executable(self, proc_info: ProcessInfo) -> bool:
        """
        Move executable to quarantine location (requires termination first).
        
        Args:
            proc_info: Process whose executable to quarantine
            
        Returns:
            True if quarantined, False otherwise
        """
        if not self.is_admin:
            self.ui.print_error("Administrator privileges required")
            return False
        
        if not os.path.exists(proc_info.path):
            self.ui.print_error(f"Executable not found: {proc_info.path}")
            return False
        
        # Warning
        self.ui.print_separator()
        self.ui.print_warning("QUARANTINE REQUEST")
        self.ui.print_info(f"Executable: {proc_info.path}")
        self.ui.print_warning(
            "⚠️  This will move the executable to a quarantine folder and may break the application!"
        )
        self.ui.print_separator()
        
        confirm = self.ui.prompt_yes_no(
            "Quarantine this executable? The process must be terminated first.",
            default=False
        )
        
        if not confirm:
            self.ui.print_info("Quarantine cancelled")
            return False
        
        # Create quarantine directory
        quarantine_dir = os.path.join(os.getcwd(), "quarantine")
        os.makedirs(quarantine_dir, exist_ok=True)
        
        try:
            import shutil
            from datetime import datetime
            
            # Generate quarantine filename with timestamp
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"{timestamp}_{os.path.basename(proc_info.path)}"
            quarantine_path = os.path.join(quarantine_dir, filename)
            
            # Move file
            shutil.move(proc_info.path, quarantine_path)
            
            self.ui.print_success(f"Executable quarantined: {quarantine_path}")
            
            # Create info file
            info_path = quarantine_path + ".info.txt"
            with open(info_path, 'w') as f:
                f.write(f"Quarantined: {datetime.now().isoformat()}\n")
                f.write(f"Original Path: {proc_info.path}\n")
                f.write(f"Process Name: {proc_info.name}\n")
                f.write(f"PID at quarantine: {proc_info.pid}\n")
                f.write(f"User: {proc_info.user_account}\n")
                f.write(f"Signed: {proc_info.is_signed}\n")
            
            self.ui.print_info(f"Quarantine info saved: {info_path}")
            
            return True
            
        except Exception as e:
            self.ui.print_error(f"Failed to quarantine: {e}")
            return False
    
    def get_process_details(self, proc_info: ProcessInfo):
        """
        Display detailed process information.
        
        Args:
            proc_info: Process to inspect
        """
        self.ui.print_separator("=")
        self.ui.print_info(f"PROCESS DETAILS: {proc_info.name} (PID {proc_info.pid})")
        self.ui.print_separator("=")
        
        details = [
            ("Process Name", proc_info.name),
            ("Process ID", proc_info.pid),
            ("Parent PID", proc_info.parent_pid),
            ("Executable Path", proc_info.path),
            ("User Account", proc_info.user_account),
            ("Digitally Signed", "Yes" if proc_info.is_signed else "No"),
            ("Hidden Window", "Yes" if proc_info.is_hidden_window else "No"),
            ("Is Service", "Yes" if proc_info.is_service else "No"),
            ("Privileges", ", ".join(proc_info.privileges)),
        ]
        
        for label, value in details:
            self.ui.print_info(f"  {label:<20}: {value}")
        
        if proc_info.loaded_dlls:
            self.ui.print_info(f"  {'Loaded DLLs':<20}:")
            for dll in proc_info.loaded_dlls[:10]:  # Show first 10
                self.ui.print_info(f"    - {dll}")
            if len(proc_info.loaded_dlls) > 10:
                self.ui.print_info(f"    ... and {len(proc_info.loaded_dlls) - 10} more")
        
        self.ui.print_separator("=")


if __name__ == "__main__":
    # Test admin actions (mock)
    from enumerator import MockEnumerator
    
    print("Testing Admin Actions Module...\n")
    
    ui = UI(use_emoji=True)
    admin = AdminActions(ui=ui)
    
    print(f"Running as admin: {admin.is_admin}\n")
    
    # Get mock process
    enum = MockEnumerator()
    proc = enum.get_process_info(4120)  # badproc.exe
    
    if proc:
        # Show details
        admin.get_process_details(proc)
        
        # Note: Actual termination/quarantine would require real confirmation
        print("\nAdmin actions available:")
        print("  - terminate_process()")
        print("  - suspend_process()")
        print("  - quarantine_executable()")
        print("\nAll actions require explicit user confirmation.")
