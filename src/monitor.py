"""
Monitor Module - Real-time hook detection and alerting.

This module provides continuous monitoring of keyboard hooks with change detection.
"""

import time
from typing import Dict, List, Set, Optional, Callable
from datetime import datetime
from dataclasses import dataclass
import threading

from enumerator import get_enumerator, HookInfo, ProcessInfo
from heuristics import HeuristicEngine, RiskAssessment, RiskLevel
from ui import UI


@dataclass
class MonitorEvent:
    """Event detected during monitoring."""
    event_type: str  # "hook_added", "hook_removed", "hook_changed", "process_changed"
    hook_info: Optional[HookInfo]
    process_info: Optional[ProcessInfo]
    risk_assessment: Optional[RiskAssessment]
    timestamp: str
    details: str


class HookMonitor:
    """
    Real-time keyboard hook monitor.
    
    Continuously scans for hooks and detects changes.
    """
    
    def __init__(self, 
                 interval: float = 2.0,
                 mock_mode: bool = False,
                 sensitivity: str = "medium",
                 ui: Optional[UI] = None):
        """
        Initialize hook monitor.
        
        Args:
            interval: Polling interval in seconds
            mock_mode: Use mock data
            sensitivity: Detection sensitivity (low/medium/high)
            ui: UI instance for output
        """
        self.interval = interval
        self.mock_mode = mock_mode
        self.sensitivity = sensitivity
        self.ui = ui or UI()
        
        # Initialize components
        self.enumerator = get_enumerator(mock_mode=mock_mode)
        self.heuristics = HeuristicEngine(sensitivity=sensitivity)
        
        # State tracking
        self.known_hooks: Dict[int, HookInfo] = {}  # hook_id -> HookInfo
        self.known_processes: Dict[int, ProcessInfo] = {}  # pid -> ProcessInfo
        self.events: List[MonitorEvent] = []
        
        # Control flags
        self.is_running = False
        self._stop_requested = False
        self._monitor_thread: Optional[threading.Thread] = None
        
        # Callbacks
        self.on_event_callbacks: List[Callable[[MonitorEvent], None]] = []
    
    def start(self, threaded: bool = False):
        """
        Start monitoring.
        
        Args:
            threaded: Run in background thread
        """
        if self.is_running:
            self.ui.print_warning("Monitor already running")
            return
        
        self._stop_requested = False
        
        if threaded:
            self._monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
            self._monitor_thread.start()
            self.ui.print_success("Monitor started in background")
        else:
            self._monitor_loop()
    
    def stop(self):
        """Stop monitoring gracefully."""
        if not self.is_running:
            return
        
        self.ui.print_info("Stopping monitor...")
        self._stop_requested = True
        
        if self._monitor_thread and self._monitor_thread.is_alive():
            self._monitor_thread.join(timeout=5.0)
        
        self.is_running = False
        self.ui.print_success("Monitor stopped")
    
    def _monitor_loop(self):
        """Main monitoring loop."""
        self.is_running = True
        self.ui.print_info(f"Starting real-time monitoring (interval: {self.interval}s)...")
        self.ui.print_info("Press Ctrl+C to stop")
        self.ui.print_separator()
        
        # Initial scan
        self._perform_scan()
        
        try:
            scan_count = 1
            
            while not self._stop_requested:
                time.sleep(self.interval)
                
                scan_count += 1
                self.ui.print_info(f"Scan #{scan_count} at {self._get_timestamp()}")
                
                # Perform scan and detect changes
                self._perform_scan()
                
        except KeyboardInterrupt:
            self.ui.print_info("\nMonitoring interrupted by user")
        finally:
            self.is_running = False
    
    def _perform_scan(self):
        """Perform a single scan for hooks and changes."""
        try:
            # Detect current hooks
            current_hooks = self.enumerator.detect_hooks()
            current_hook_ids = {hook.hook_id for hook in current_hooks}
            known_hook_ids = set(self.known_hooks.keys())
            
            # Detect new hooks
            new_hook_ids = current_hook_ids - known_hook_ids
            for hook_id in new_hook_ids:
                hook = next(h for h in current_hooks if h.hook_id == hook_id)
                self._handle_new_hook(hook)
            
            # Detect removed hooks
            removed_hook_ids = known_hook_ids - current_hook_ids
            for hook_id in removed_hook_ids:
                self._handle_removed_hook(hook_id)
            
            # Update process information for existing hooks
            for hook in current_hooks:
                if hook.hook_id in self.known_hooks:
                    self._check_process_changes(hook)
            
            # Update known state
            self.known_hooks = {hook.hook_id: hook for hook in current_hooks}
            
        except Exception as e:
            self.ui.print_error(f"Error during scan: {e}")
    
    def _handle_new_hook(self, hook: HookInfo):
        """Handle detection of a new hook."""
        # Get process info
        proc_info = self.enumerator.get_process_info(hook.owner_pid)
        
        if not proc_info:
            self.ui.print_warning(f"New hook detected but cannot access process {hook.owner_pid}")
            return
        
        # Analyze risk
        assessment = self.heuristics.analyze_hook(hook, proc_info)
        
        # Create event
        event = MonitorEvent(
            event_type="hook_added",
            hook_info=hook,
            process_info=proc_info,
            risk_assessment=assessment,
            timestamp=self._get_timestamp(),
            details=f"New {hook.hook_type} hook from {proc_info.name} (PID {hook.owner_pid})"
        )
        
        self.events.append(event)
        self.known_processes[hook.owner_pid] = proc_info
        
        # Alert user
        self._alert_event(event)
        
        # Trigger callbacks
        for callback in self.on_event_callbacks:
            try:
                callback(event)
            except Exception as e:
                self.ui.print_error(f"Callback error: {e}")
    
    def _handle_removed_hook(self, hook_id: int):
        """Handle removal of a hook."""
        removed_hook = self.known_hooks[hook_id]
        
        event = MonitorEvent(
            event_type="hook_removed",
            hook_info=removed_hook,
            process_info=self.known_processes.get(removed_hook.owner_pid),
            risk_assessment=None,
            timestamp=self._get_timestamp(),
            details=f"Hook {hook_id} removed from {removed_hook.owner_process} (PID {removed_hook.owner_pid})"
        )
        
        self.events.append(event)
        
        # Info level alert for removals
        self.ui.print_info(f"Hook removed: {event.details}")
        
        # Trigger callbacks
        for callback in self.on_event_callbacks:
            try:
                callback(event)
            except Exception as e:
                self.ui.print_error(f"Callback error: {e}")
    
    def _check_process_changes(self, hook: HookInfo):
        """Check if process information changed for existing hook."""
        old_proc = self.known_processes.get(hook.owner_pid)
        new_proc = self.enumerator.get_process_info(hook.owner_pid)
        
        if not new_proc:
            return
        
        # Check for significant changes
        changed = False
        changes = []
        
        if old_proc:
            if old_proc.path != new_proc.path:
                changes.append(f"path changed from {old_proc.path} to {new_proc.path}")
                changed = True
            
            if old_proc.is_signed != new_proc.is_signed:
                changes.append(f"signature status changed")
                changed = True
            
            if old_proc.loaded_dlls != new_proc.loaded_dlls:
                new_dlls = set(new_proc.loaded_dlls) - set(old_proc.loaded_dlls)
                if new_dlls:
                    changes.append(f"loaded new DLLs: {', '.join(list(new_dlls)[:3])}")
                    changed = True
        
        if changed:
            # Re-analyze with updated info
            assessment = self.heuristics.analyze_hook(hook, new_proc)
            
            event = MonitorEvent(
                event_type="process_changed",
                hook_info=hook,
                process_info=new_proc,
                risk_assessment=assessment,
                timestamp=self._get_timestamp(),
                details=f"Process {new_proc.name} changed: {'; '.join(changes)}"
            )
            
            self.events.append(event)
            self.known_processes[hook.owner_pid] = new_proc
            
            # Alert if high risk
            if assessment.risk_level == RiskLevel.HIGH:
                self._alert_event(event)
    
    def _alert_event(self, event: MonitorEvent):
        """Display alert for event."""
        if event.risk_assessment:
            level_map = {
                RiskLevel.HIGH: "HIGH",
                RiskLevel.MEDIUM: "MEDIUM",
                RiskLevel.LOW: "LOW",
                RiskLevel.UNKNOWN: "UNKNOWN",
            }
            
            risk_str = level_map.get(event.risk_assessment.risk_level, "UNKNOWN")
            
            # Create detailed alert message
            msg = (
                f"{event.details} | "
                f"Risk: {risk_str} ({event.risk_assessment.risk_score}/100)"
            )
            
            if event.risk_assessment.triggered_rules:
                rules = [r.name for r in event.risk_assessment.triggered_rules[:2]]
                msg += f" | Flags: {', '.join(rules)}"
            
            # Use UI alert with appropriate level
            from ui import RiskLevel as UIRiskLevel
            
            ui_level_map = {
                RiskLevel.HIGH: UIRiskLevel.HIGH,
                RiskLevel.MEDIUM: UIRiskLevel.MEDIUM,
                RiskLevel.LOW: UIRiskLevel.LOW,
            }
            
            ui_level = ui_level_map.get(event.risk_assessment.risk_level, UIRiskLevel.UNKNOWN)
            self.ui.print_alert(ui_level, msg)
        else:
            self.ui.print_info(event.details)
    
    def snapshot(self) -> List[Dict]:
        """
        Take snapshot of current hooks.
        
        Returns:
            List of hook/process/assessment data
        """
        self.ui.print_info("Taking snapshot of current hooks...")
        
        hooks = self.enumerator.detect_hooks()
        snapshot_data = []
        
        for hook in hooks:
            proc_info = self.enumerator.get_process_info(hook.owner_pid)
            
            if proc_info:
                assessment = self.heuristics.analyze_hook(hook, proc_info)
                
                snapshot_data.append({
                    "hook": hook,
                    "process": proc_info,
                    "assessment": assessment,
                    "timestamp": self._get_timestamp()
                })
        
        self.ui.print_success(f"Snapshot complete: {len(snapshot_data)} hooks found")
        
        return snapshot_data
    
    def get_events(self, 
                   event_type: Optional[str] = None,
                   min_risk: Optional[RiskLevel] = None) -> List[MonitorEvent]:
        """
        Get filtered events.
        
        Args:
            event_type: Filter by event type
            min_risk: Minimum risk level to include
            
        Returns:
            Filtered list of events
        """
        filtered = self.events
        
        if event_type:
            filtered = [e for e in filtered if e.event_type == event_type]
        
        if min_risk:
            risk_order = {
                RiskLevel.LOW: 0,
                RiskLevel.MEDIUM: 1,
                RiskLevel.HIGH: 2,
                RiskLevel.UNKNOWN: -1,
            }
            min_level = risk_order[min_risk]
            
            filtered = [
                e for e in filtered
                if e.risk_assessment and risk_order.get(e.risk_assessment.risk_level, -1) >= min_level
            ]
        
        return filtered
    
    def add_event_callback(self, callback: Callable[[MonitorEvent], None]):
        """
        Add callback to be called on each event.
        
        Args:
            callback: Function that takes MonitorEvent
        """
        self.on_event_callbacks.append(callback)
    
    @staticmethod
    def _get_timestamp() -> str:
        """Get current timestamp."""
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


if __name__ == "__main__":
    # Test monitor
    print("Testing Hook Monitor (Mock Mode)...\n")
    
    ui = UI(use_emoji=True)
    monitor = HookMonitor(interval=3.0, mock_mode=True, ui=ui)
    
    # Add event callback
    def log_event(event: MonitorEvent):
        print(f"  [Callback] {event.event_type}: {event.details}")
    
    monitor.add_event_callback(log_event)
    
    # Take initial snapshot
    snapshot = monitor.snapshot()
    
    print("\nSnapshot Results:")
    for i, item in enumerate(snapshot, 1):
        hook = item["hook"]
        proc = item["process"]
        assess = item["assessment"]
        
        print(f"\n  {i}. {proc.name} (PID {proc.pid})")
        print(f"     Hook Type: {hook.hook_type}")
        print(f"     Risk: {assess.risk_level.value} ({assess.risk_score}/100)")
        if assess.triggered_rules:
            print(f"     Rules: {', '.join(r.name for r in assess.triggered_rules)}")
    
    # Run monitor for short duration
    print("\n\nStarting monitoring (will run for 10 seconds)...")
    print("=" * 70)
    
    try:
        monitor.start(threaded=True)
        time.sleep(10)
        monitor.stop()
    except KeyboardInterrupt:
        monitor.stop()
    
    print("\n\nMonitoring complete!")
    print(f"Total events captured: {len(monitor.events)}")
