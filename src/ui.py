"""
UI Module - CLI rendering, colors, ASCII banner, menu, and table formatting.

This module provides all visual elements for the Anti-Keylogger Tool CLI.
"""

from typing import List, Dict, Any, Optional
from enum import Enum
import sys

try:
    from colorama import init, Fore, Back, Style
    init(autoreset=True)
except ImportError:
    # Fallback if colorama not available
    class Fore:
        RED = YELLOW = GREEN = CYAN = MAGENTA = BLUE = WHITE = RESET = ""
    class Style:
        BRIGHT = DIM = RESET_ALL = ""
    class Back:
        RED = GREEN = YELLOW = BLUE = BLACK = RESET = ""


class RiskLevel(Enum):
    """Risk level classification."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    UNKNOWN = "UNKNOWN"


class UI:
    """Terminal UI manager for Anti-Keylogger Tool."""
    
    def __init__(self, use_emoji: bool = True, quiet: bool = False):
        """
        Initialize UI manager.
        
        Args:
            use_emoji: Enable emoji indicators (✅/⚠️/❌)
            quiet: Minimize output
        """
        self.use_emoji = use_emoji
        self.quiet = quiet
        self.width = 70  # Default console width for boxes
        
    def clear_screen(self):
        """Clear the terminal screen."""
        if not self.quiet:
            print("\033[2J\033[H", end="")
    
    def print_banner(self):
        """Display ASCII art banner with version and legal notice."""
        if self.quiet:
            return
            
        banner = f"""{Fore.CYAN}{Style.BRIGHT}
██╗  ██╗███████╗██╗   ██╗███████╗████████╗██████╗  ██████╗ ██╗  ██╗███████╗
██║ ██╔╝██╔════╝╚██╗ ██╔╝██╔════╝╚══██╔══╝██╔══██╗██╔═══██╗██║ ██╔╝██╔════╝
█████╔╝ █████╗   ╚████╔╝ ███████╗   ██║   ██████╔╝██║   ██║█████╔╝ █████╗  
██╔═██╗ ██╔══╝    ╚██╔╝  ╚════██║   ██║   ██╔══██╗██║   ██║██╔═██╗ ██╔══╝  
██║  ██╗███████╗   ██║   ███████║   ██║   ██║  ██║╚██████╔╝██║  ██╗███████╗
╚═╝  ╚═╝╚══════╝   ╚═╝   ╚══════╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝
                                                                             
    ██╗  ██╗ ██████╗  ██████╗ ██╗  ██╗                                      
    ██║  ██║██╔═══██╗██╔═══██╗██║ ██╔╝                                      
    ███████║██║   ██║██║   ██║█████╔╝                                       
    ██╔══██║██║   ██║██║   ██║██╔═██╗                                       
    ██║  ██║╚██████╔╝╚██████╔╝██║  ██╗                                      
    ╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝                                      
                                                                             
   █████╗ ███╗   ██╗ ██████╗ ███╗   ███╗ █████╗ ██╗  ██╗   ██╗             
  ██╔══██╗████╗  ██║██╔═══██╗████╗ ████║██╔══██╗██║  ╚██╗ ██╔╝             
  ███████║██╔██╗ ██║██║   ██║██╔████╔██║███████║██║   ╚████╔╝              
  ██╔══██║██║╚██╗██║██║   ██║██║╚██╔╝██║██╔══██║██║    ╚██╔╝               
  ██║  ██║██║ ╚████║╚██████╔╝██║ ╚═╝ ██║██║  ██║███████╗██║                
  ╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝╚═╝                
                                                                             
 ██████╗ ███████╗████████╗███████╗ ██████╗████████╗ ██████╗ ██████╗        
 ██╔══██╗██╔════╝╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝██╔═══██╗██╔══██╗       
 ██║  ██║█████╗     ██║   █████╗  ██║        ██║   ██║   ██║██████╔╝       
 ██║  ██║██╔══╝     ██║   ██╔══╝  ██║        ██║   ██║   ██║██╔══██╗       
 ██████╔╝███████╗   ██║   ███████╗╚██████╗   ██║   ╚██████╔╝██║  ██║       
 ╚═════╝ ╚══════╝   ╚═╝   ╚══════╝ ╚═════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝       
{Style.RESET_ALL}
{Fore.YELLOW}v1.0 — Keystroke Hook Anomaly Detector (defensive only){Style.RESET_ALL}

{Fore.RED}{Style.BRIGHT}[LEGAL] This tool does NOT capture keystrokes. Use only with consent.{Style.RESET_ALL}
{Style.DIM}Do you agree to proceed? (yes/no): {Style.RESET_ALL}"""
        
        print(banner, end="")
    
    def print_menu(self):
        """Display main menu in a formatted box."""
        if self.quiet:
            return
            
        menu = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════════════╗
║  {Style.BRIGHT}MAIN MENU{Style.RESET_ALL}{Fore.CYAN}                                                         ║
╠══════════════════════════════════════════════════════════════════════╣
║  {Fore.GREEN}[1]{Fore.WHITE} Start monitoring (real-time){Fore.CYAN}                                   ║
║  {Fore.GREEN}[2]{Fore.WHITE} Snapshot current hooks{Fore.CYAN}                                         ║
║  {Fore.GREEN}[3]{Fore.WHITE} List all processes & hooks{Fore.CYAN}                                     ║
║  {Fore.GREEN}[4]{Fore.WHITE} View detection history & reports{Fore.CYAN}                               ║
║  {Fore.GREEN}[5]{Fore.WHITE} Export report (json/csv){Fore.CYAN}                                       ║
║  {Fore.YELLOW}[0]{Fore.WHITE} Exit{Fore.CYAN}                                                            ║
╚══════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}

{Style.DIM}Enter choice: {Style.RESET_ALL}"""
        
        print(menu, end="")
    
    def print_table(self, headers: List[str], rows: List[List[Any]], 
                   risk_column: Optional[int] = None):
        """
        Print formatted table with column alignment.
        
        Args:
            headers: Column headers
            rows: Data rows
            risk_column: Index of risk level column for color coding
        """
        if self.quiet:
            return
        
        # Calculate column widths
        col_widths = [len(h) for h in headers]
        for row in rows:
            for i, cell in enumerate(row):
                col_widths[i] = max(col_widths[i], len(str(cell)))
        
        # Print header
        header_line = "  ".join(
            h.ljust(col_widths[i]) for i, h in enumerate(headers)
        )
        print(f"\n{Fore.CYAN}{Style.BRIGHT}{header_line}{Style.RESET_ALL}")
        print("─" * sum(col_widths) + "─" * (len(headers) * 2 - 2))
        
        # Print rows
        for row in rows:
            formatted_cells = []
            for i, cell in enumerate(row):
                cell_str = str(cell).ljust(col_widths[i])
                
                # Apply color coding for risk column
                if i == risk_column:
                    cell_str = self._colorize_risk(cell_str, str(cell))
                
                formatted_cells.append(cell_str)
            
            print("  ".join(formatted_cells))
    
    def _colorize_risk(self, text: str, risk: str) -> str:
        """Apply color to risk level text."""
        risk_upper = risk.upper().strip()
        
        if "HIGH" in risk_upper:
            icon = "❌" if self.use_emoji else "!"
            return f"{Fore.RED}{Style.BRIGHT}{icon} {text}{Style.RESET_ALL}"
        elif "MEDIUM" in risk_upper:
            icon = "⚠️ " if self.use_emoji else "?"
            return f"{Fore.YELLOW}{icon} {text}{Style.RESET_ALL}"
        elif "LOW" in risk_upper:
            icon = "✅" if self.use_emoji else "√"
            return f"{Fore.GREEN}{icon} {text}{Style.RESET_ALL}"
        else:
            return f"{Fore.WHITE}{text}{Style.RESET_ALL}"
    
    def print_alert(self, level: RiskLevel, message: str):
        """
        Print colored alert message.
        
        Args:
            level: Alert severity level
            message: Alert message
        """
        if self.quiet and level != RiskLevel.HIGH:
            return
        
        timestamp = self._get_timestamp()
        
        if level == RiskLevel.HIGH:
            icon = "❌" if self.use_emoji else "[!]"
            print(f"{Fore.RED}{Style.BRIGHT}{icon} {timestamp} HIGH: {message}{Style.RESET_ALL}")
        elif level == RiskLevel.MEDIUM:
            icon = "⚠️ " if self.use_emoji else "[?]"
            print(f"{Fore.YELLOW}{icon} {timestamp} MEDIUM: {message}{Style.RESET_ALL}")
        elif level == RiskLevel.LOW:
            icon = "✅" if self.use_emoji else "[√]"
            print(f"{Fore.GREEN}{icon} {timestamp} LOW: {message}{Style.RESET_ALL}")
        else:
            print(f"{Style.DIM}[i] {timestamp} {message}{Style.RESET_ALL}")
    
    def print_info(self, message: str):
        """Print informational message."""
        if not self.quiet:
            print(f"{Fore.CYAN}[i]{Style.RESET_ALL} {message}")
    
    def print_success(self, message: str):
        """Print success message."""
        if not self.quiet:
            icon = "✅" if self.use_emoji else "[√]"
            print(f"{Fore.GREEN}{icon} {message}{Style.RESET_ALL}")
    
    def print_warning(self, message: str):
        """Print warning message."""
        if not self.quiet:
            icon = "⚠️ " if self.use_emoji else "[!]"
            print(f"{Fore.YELLOW}{icon} {message}{Style.RESET_ALL}")
    
    def print_error(self, message: str):
        """Print error message."""
        icon = "❌" if self.use_emoji else "[X]"
        print(f"{Fore.RED}{Style.BRIGHT}{icon} ERROR: {message}{Style.RESET_ALL}", 
              file=sys.stderr)
    
    def print_progress(self, current: int, total: int, prefix: str = "Progress"):
        """
        Print progress indicator.
        
        Args:
            current: Current progress value
            total: Total target value
            prefix: Progress message prefix
        """
        if self.quiet:
            return
        
        percentage = (current / total * 100) if total > 0 else 0
        print(f"{Style.DIM}{prefix}: {current}/{total} ({percentage:.1f}%){Style.RESET_ALL}", 
              end='\r')
        
        if current >= total:
            print()  # New line when complete
    
    def print_separator(self, char: str = "─", length: Optional[int] = None):
        """Print horizontal separator line."""
        if not self.quiet:
            length = length or self.width
            print(f"{Style.DIM}{char * length}{Style.RESET_ALL}")
    
    def prompt_input(self, message: str, default: Optional[str] = None) -> str:
        """
        Prompt user for input.
        
        Args:
            message: Prompt message
            default: Default value if empty input
            
        Returns:
            User input string
        """
        if default:
            prompt = f"{Fore.CYAN}{message} [{default}]: {Style.RESET_ALL}"
        else:
            prompt = f"{Fore.CYAN}{message}: {Style.RESET_ALL}"
        
        response = input(prompt).strip()
        return response if response else (default or "")
    
    def prompt_yes_no(self, message: str, default: bool = False) -> bool:
        """
        Prompt user for yes/no confirmation.
        
        Args:
            message: Question to ask
            default: Default value if empty input
            
        Returns:
            True for yes, False for no
        """
        default_str = "yes" if default else "no"
        response = self.prompt_input(f"{message} (yes/no)", default_str)
        return response.lower() in ["yes", "y", "true", "1"]
    
    def print_legal_warning(self) -> bool:
        """
        Display legal/ethical warning and get consent.
        
        Returns:
            True if user consents, False otherwise
        """
        warning = f"""
{Fore.RED}{Style.BRIGHT}╔══════════════════════════════════════════════════════════════════════╗
║  LEGAL & ETHICAL WARNING                                             ║
╚══════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}

{Fore.YELLOW}This tool monitors system hooks for defensive security purposes.{Style.RESET_ALL}

{Style.BRIGHT}IMPORTANT NOTICES:{Style.RESET_ALL}

  {Fore.RED}1.{Style.RESET_ALL} This tool does {Style.BRIGHT}NOT{Style.RESET_ALL} capture or log keystrokes
  {Fore.RED}2.{Style.RESET_ALL} Only use on systems you {Style.BRIGHT}OWN{Style.RESET_ALL} or have {Style.BRIGHT}WRITTEN PERMISSION{Style.RESET_ALL} to monitor
  {Fore.RED}3.{Style.RESET_ALL} Unauthorized monitoring may violate:
      - Computer Fraud and Abuse Act (CFAA, USA)
      - General Data Protection Regulation (GDPR, EU)
      - Electronic Communications Privacy Act (ECPA)
      - Local privacy and surveillance laws
  {Fore.RED}4.{Style.RESET_ALL} You are {Style.BRIGHT}SOLELY RESPONSIBLE{Style.RESET_ALL} for compliance with applicable laws
  {Fore.RED}5.{Style.RESET_ALL} The authors accept {Style.BRIGHT}NO LIABILITY{Style.RESET_ALL} for misuse

{Fore.GREEN}By proceeding, you acknowledge:{Style.RESET_ALL}
  ✓ You have legal authorization to monitor this system
  ✓ You understand the tool's purpose and limitations
  ✓ You accept full responsibility for your use of this tool

"""
        print(warning)
        
        consent = self.prompt_yes_no(
            f"{Fore.CYAN}{Style.BRIGHT}Do you agree to these terms and wish to proceed?{Style.RESET_ALL}",
            default=False
        )
        
        if consent:
            self.print_success("Consent acknowledged. Proceeding...")
        else:
            self.print_warning("Consent denied. Exiting.")
        
        return consent
    
    @staticmethod
    def _get_timestamp() -> str:
        """Get current timestamp in ISO format."""
        from datetime import datetime
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# Convenience functions for quick access
def print_banner(use_emoji: bool = True):
    """Print banner (convenience function)."""
    ui = UI(use_emoji=use_emoji)
    ui.print_banner()


def print_menu():
    """Print menu (convenience function)."""
    ui = UI()
    ui.print_menu()


def get_consent(use_emoji: bool = True) -> bool:
    """Get user consent (convenience function)."""
    ui = UI(use_emoji=use_emoji)
    return ui.print_legal_warning()


if __name__ == "__main__":
    # Demo UI elements
    ui = UI(use_emoji=True)
    ui.print_banner()
    input()
    ui.clear_screen()
    ui.print_menu()
    
    # Demo table
    ui.print_table(
        headers=["ID", "PID", "Process", "HookType", "Risk", "Notes"],
        rows=[
            [1, 4120, "badproc.exe", "WH_KEYBOARD_LL", "HIGH", "unsigned, hidden window"],
            [2, 2248, "explorer.exe", "WH_KEYBOARD_LL", "LOW", "signed system process"],
            [3, 8192, "unknown.exe", "WH_KEYBOARD", "MEDIUM", "unsigned"],
        ],
        risk_column=4
    )
    
    # Demo alerts
    ui.print_alert(RiskLevel.HIGH, "Suspicious hook detected from badproc.exe")
    ui.print_alert(RiskLevel.MEDIUM, "Unsigned process monitoring detected")
    ui.print_alert(RiskLevel.LOW, "System hook enumeration complete")
    
    ui.print_success("Operation completed successfully")
    ui.print_warning("Some features require admin privileges")
    ui.print_error("Access denied to process 1234")
