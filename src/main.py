"""
Main Entry Point - Anti-Keylogger Tool CLI

This is the main entry point for the Anti-Keylogger Tool.
Handles consent flow, command-line arguments, and menu navigation.
"""

import argparse
import sys
import os
from datetime import datetime
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ui import UI, get_consent
from enumerator import get_enumerator
from heuristics import HeuristicEngine, RiskLevel
from monitor import HookMonitor
from report import ReportGenerator, Logger
from admin_actions import AdminActions


# Consent tracking
CONSENT_FILE = Path(".consent")


def check_consent() -> bool:
    """
    Check if user has previously given consent.
    
    Returns:
        True if consent is valid, False if needs re-consent
    """
    if not CONSENT_FILE.exists():
        return False
    
    try:
        with open(CONSENT_FILE, 'r') as f:
            consent_data = f.read().strip()
            # Check if consent is recent (within 30 days)
            consent_date = datetime.fromisoformat(consent_data)
            age_days = (datetime.now() - consent_date).days
            
            return age_days < 30
    except:
        return False


def save_consent():
    """Save consent timestamp."""
    with open(CONSENT_FILE, 'w') as f:
        f.write(datetime.now().isoformat())


class AntiKeyloggerCLI:
    """Main CLI application."""
    
    def __init__(self, args):
        """
        Initialize CLI application.
        
        Args:
            args: Parsed command-line arguments
        """
        self.args = args
        self.ui = UI(
            use_emoji=not args.no_emoji,
            quiet=args.quiet
        )
        
        # Initialize components
        self.enumerator = get_enumerator(mock_mode=args.mock)
        self.heuristics = HeuristicEngine(sensitivity="medium")
        self.monitor = HookMonitor(
            interval=args.interval,
            mock_mode=args.mock,
            sensitivity="medium",
            ui=self.ui
        )
        self.reporter = ReportGenerator(output_dir=args.output_dir)
        self.logger = Logger(log_file=f"{args.output_dir}/detection.log")
        self.admin = AdminActions(ui=self.ui) if args.admin else None
        
        # State
        self.running = True
        self.last_snapshot = []
    
    def run(self):
        """Main application loop."""
        # Consent check
        if not check_consent():
            self.ui.print_banner()
            if not get_consent(use_emoji=not self.args.no_emoji):
                self.ui.print_error("Consent required to proceed. Exiting.")
                sys.exit(1)
            save_consent()
        else:
            if not self.args.quiet:
                self.ui.print_banner()
                input()  # Wait for user to press Enter
        
        # Clear screen and show menu
        self.ui.clear_screen()
        
        # JSON mode - non-interactive
        if self.args.json:
            self.json_mode()
            return
        
        # Interactive menu mode
        while self.running:
            try:
                self.ui.print_menu()
                choice = input().strip()
                
                if choice == "1":
                    self.start_monitoring()
                elif choice == "2":
                    self.snapshot_current()
                elif choice == "3":
                    self.list_all_processes()
                elif choice == "4":
                    self.view_history()
                elif choice == "5":
                    self.export_report()
                elif choice == "0":
                    self.exit_app()
                else:
                    self.ui.print_error("Invalid choice. Please select 0-5.")
                    
            except KeyboardInterrupt:
                self.ui.print_info("\nInterrupted by user")
                self.exit_app()
            except Exception as e:
                self.ui.print_error(f"Unexpected error: {e}")
    
    def json_mode(self):
        """Run in JSON output mode (non-interactive)."""
        import json
        
        # Take snapshot
        snapshot = self.monitor.snapshot()
        
        # Convert to JSON-serializable format
        output = {
            "timestamp": datetime.now().isoformat(),
            "total_hooks": len(snapshot),
            "hooks": []
        }
        
        for item in snapshot:
            hook = item["hook"]
            proc = item["process"]
            assess = item["assessment"]
            
            output["hooks"].append({
                "hook_id": hook.hook_id,
                "hook_type": hook.hook_type,
                "pid": proc.pid,
                "process": proc.name,
                "path": proc.path,
                "risk_score": assess.risk_score,
                "risk_level": assess.risk_level.value,
                "is_signed": proc.is_signed,
            })
        
        print(json.dumps(output, indent=2))
    
    def start_monitoring(self):
        """Start real-time monitoring."""
        self.ui.clear_screen()
        self.ui.print_info("Starting real-time monitoring...")
        self.ui.print_info(f"Polling interval: {self.args.interval} seconds")
        self.ui.print_info("Press Ctrl+C to stop and return to menu")
        self.ui.print_separator()
        
        # Add logging callback
        self.monitor.add_event_callback(lambda event: self.logger.log_event(event))
        
        try:
            self.monitor.start(threaded=False)
        except KeyboardInterrupt:
            self.monitor.stop()
            self.ui.print_info("Monitoring stopped")
        
        input("\nPress Enter to return to menu...")
    
    def snapshot_current(self):
        """Take snapshot of current hooks."""
        self.ui.clear_screen()
        self.ui.print_info("Taking snapshot of current hooks...")
        
        snapshot = self.monitor.snapshot()
        self.last_snapshot = snapshot
        
        if not snapshot:
            self.ui.print_warning("No hooks detected")
            input("\nPress Enter to return to menu...")
            return
        
        # Display as table
        headers = ["ID", "PID", "Process", "HookType", "Risk", "Notes"]
        rows = []
        
        for i, item in enumerate(snapshot, 1):
            hook = item["hook"]
            proc = item["process"]
            assess = item["assessment"]
            
            # Build notes
            notes = []
            if not proc.is_signed:
                notes.append("unsigned")
            if proc.is_hidden_window:
                notes.append("hidden window")
            if assess.triggered_rules:
                notes.append(f"{len(assess.triggered_rules)} flags")
            
            notes_str = ", ".join(notes) if notes else "—"
            
            rows.append([
                i,
                proc.pid,
                proc.name,
                hook.hook_type,
                assess.risk_level.value,
                notes_str
            ])
        
        self.ui.print_table(headers, rows, risk_column=4)
        
        # Show statistics
        self.ui.print_separator()
        self.ui.print_info(f"Total hooks: {len(snapshot)}")
        
        risk_counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0}
        for item in snapshot:
            level = item["assessment"].risk_level.value
            risk_counts[level] = risk_counts.get(level, 0) + 1
        
        self.ui.print_info(
            f"Risk distribution: "
            f"{risk_counts['HIGH']} high, "
            f"{risk_counts['MEDIUM']} medium, "
            f"{risk_counts['LOW']} low"
        )
        
        input("\nPress Enter to return to menu...")
    
    def list_all_processes(self):
        """List all processes with hook potential."""
        self.ui.clear_screen()
        self.ui.print_info("Enumerating all processes...")
        
        pids = self.enumerator.enumerate_processes()
        self.ui.print_info(f"Found {len(pids)} processes")
        
        # Filter to show only interesting processes
        interesting = []
        
        for pid in pids[:50]:  # Limit to first 50 for display
            proc = self.enumerator.get_process_info(pid)
            if proc:
                assessment = self.heuristics.analyze_process(proc)
                
                # Show if medium/high risk or has user32.dll loaded
                if (assessment.risk_level in [RiskLevel.MEDIUM, RiskLevel.HIGH] or
                    any("user32" in dll.lower() for dll in proc.loaded_dlls)):
                    interesting.append((proc, assessment))
        
        if not interesting:
            self.ui.print_warning("No interesting processes found")
            input("\nPress Enter to return to menu...")
            return
        
        # Display table
        headers = ["PID", "Process", "Path", "Risk", "Notes"]
        rows = []
        
        for proc, assess in interesting:
            notes = []
            if not proc.is_signed:
                notes.append("unsigned")
            if proc.is_hidden_window:
                notes.append("hidden")
            
            rows.append([
                proc.pid,
                proc.name,
                proc.path[:50] + "..." if len(proc.path) > 50 else proc.path,
                assess.risk_level.value,
                ", ".join(notes) if notes else "—"
            ])
        
        self.ui.print_table(headers, rows, risk_column=3)
        
        # Admin actions
        if self.admin:
            self.ui.print_separator()
            self.ui.print_info("Admin mode enabled. You can inspect or act on processes.")
            
            pid_str = self.ui.prompt_input(
                "Enter PID to inspect (or press Enter to skip)",
                default=""
            )
            
            if pid_str.isdigit():
                pid = int(pid_str)
                proc = next((p for p, _ in interesting if p.pid == pid), None)
                
                if proc:
                    self.admin.get_process_details(proc)
                    
                    action = self.ui.prompt_input(
                        "Action: [t]erminate, [s]uspend, [q]uarantine, [Enter] to skip",
                        default=""
                    )
                    
                    if action.lower() == "t":
                        self.admin.terminate_process(proc)
                    elif action.lower() == "s":
                        self.admin.suspend_process(proc)
                    elif action.lower() == "q":
                        self.admin.quarantine_executable(proc)
        
        input("\nPress Enter to return to menu...")
    
    def view_history(self):
        """View detection history and events."""
        self.ui.clear_screen()
        self.ui.print_info("Detection History")
        self.ui.print_separator()
        
        events = self.monitor.get_events()
        
        if not events:
            self.ui.print_warning("No events recorded yet. Start monitoring to capture events.")
            input("\nPress Enter to return to menu...")
            return
        
        # Show last 20 events
        recent_events = events[-20:]
        
        for event in recent_events:
            timestamp = event.timestamp
            event_type = event.event_type.replace("_", " ").title()
            
            if event.risk_assessment:
                risk = event.risk_assessment.risk_level.value
                score = event.risk_assessment.risk_score
                self.ui.print_info(
                    f"[{timestamp}] {event_type} | Risk: {risk} ({score}) | {event.details}"
                )
            else:
                self.ui.print_info(f"[{timestamp}] {event_type} | {event.details}")
        
        self.ui.print_separator()
        self.ui.print_info(f"Showing {len(recent_events)} of {len(events)} total events")
        
        input("\nPress Enter to return to menu...")
    
    def export_report(self):
        """Export detection report."""
        self.ui.clear_screen()
        self.ui.print_info("Export Report")
        self.ui.print_separator()
        
        if not self.last_snapshot:
            self.ui.print_warning("No snapshot data available. Take a snapshot first (option 2).")
            input("\nPress Enter to return to menu...")
            return
        
        # Choose format
        format_choice = self.ui.prompt_input(
            "Export format: [j]son, [c]sv, [b]oth",
            default="b"
        )
        
        try:
            files_created = []
            
            if format_choice.lower() in ["j", "b"]:
                json_file = self.reporter.export_snapshot_json(self.last_snapshot)
                files_created.append(json_file)
                self.ui.print_success(f"JSON exported: {json_file}")
            
            if format_choice.lower() in ["c", "b"]:
                csv_file = self.reporter.export_snapshot_csv(self.last_snapshot)
                files_created.append(csv_file)
                self.ui.print_success(f"CSV exported: {csv_file}")
            
            # Also export events if any
            events = self.monitor.get_events()
            if events:
                events_file = self.reporter.export_events_json(events)
                files_created.append(events_file)
                self.ui.print_success(f"Events exported: {events_file}")
            
            # Export summary
            summary_file = self.reporter.export_summary_json(self.last_snapshot, events)
            files_created.append(summary_file)
            self.ui.print_success(f"Summary exported: {summary_file}")
            
            self.ui.print_separator()
            self.ui.print_info(f"Total files created: {len(files_created)}")
            
        except Exception as e:
            self.ui.print_error(f"Export failed: {e}")
        
        input("\nPress Enter to return to menu...")
    
    def exit_app(self):
        """Exit application gracefully."""
        self.ui.print_info("Shutting down...")
        
        # Stop monitor if running
        if self.monitor.is_running:
            self.monitor.stop()
        
        self.ui.print_success("Thank you for using Anti-Keylogger Tool!")
        self.running = False
        sys.exit(0)


def main():
    """Main entry point with argument parsing."""
    parser = argparse.ArgumentParser(
        description="Anti-Keylogger Tool — Keystroke Hook Anomaly Detector",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py                    # Normal mode with menu
  python main.py --admin            # Admin mode (requires elevation)
  python main.py --mock             # Mock mode for testing
  python main.py --json --quiet     # JSON output only
  python main.py --interval 5       # Custom polling interval

Legal Notice:
  This tool is for defensive security purposes only.
  Only use on systems you own or have explicit permission to monitor.
  Unauthorized use may violate privacy laws.
        """
    )
    
    parser.add_argument(
        "--admin",
        action="store_true",
        help="Enable admin mode (requires administrator privileges)"
    )
    
    parser.add_argument(
        "--mock",
        action="store_true",
        help="Use mock data instead of real Windows API (for testing)"
    )
    
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Minimize output (only show critical information)"
    )
    
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output in JSON format only (non-interactive)"
    )
    
    parser.add_argument(
        "--no-emoji",
        action="store_true",
        help="Disable emoji icons in output"
    )
    
    parser.add_argument(
        "--interval",
        type=float,
        default=2.0,
        help="Polling interval in seconds for real-time monitoring (default: 2.0)"
    )
    
    parser.add_argument(
        "--output-dir",
        type=str,
        default="./reports",
        help="Directory for reports and logs (default: ./reports)"
    )
    
    args = parser.parse_args()
    
    # Create and run CLI app
    app = AntiKeyloggerCLI(args)
    app.run()


if __name__ == "__main__":
    main()
