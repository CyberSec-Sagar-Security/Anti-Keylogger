"""
Report Module - JSON/CSV export and structured logging.

This module handles generation and export of detection reports.
"""

import json
import csv
from typing import List, Dict, Any, Optional
from datetime import datetime
from pathlib import Path
import os

from enumerator import ProcessInfo, HookInfo
from heuristics import RiskAssessment, RiskRule
from monitor import MonitorEvent


class ReportGenerator:
    """Generate structured reports from detection data."""
    
    def __init__(self, output_dir: str = "./reports"):
        """
        Initialize report generator.
        
        Args:
            output_dir: Directory for report output
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def export_snapshot_json(self, 
                            snapshot_data: List[Dict],
                            filename: Optional[str] = None) -> str:
        """
        Export snapshot to JSON format.
        
        Args:
            snapshot_data: Snapshot data from monitor
            filename: Output filename (auto-generated if None)
            
        Returns:
            Path to exported file
        """
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"snapshot_{timestamp}.json"
        
        filepath = self.output_dir / filename
        
        # Convert to JSON-serializable format
        json_data = {
            "report_type": "snapshot",
            "timestamp": datetime.now().isoformat(),
            "total_hooks": len(snapshot_data),
            "hooks": []
        }
        
        for item in snapshot_data:
            hook: HookInfo = item["hook"]
            process: ProcessInfo = item["process"]
            assessment: RiskAssessment = item["assessment"]
            
            hook_entry = {
                "hook_id": hook.hook_id,
                "hook_type": hook.hook_type,
                "timestamp": hook.timestamp,
                "process": {
                    "pid": process.pid,
                    "name": process.name,
                    "path": process.path,
                    "parent_pid": process.parent_pid,
                    "is_signed": process.is_signed,
                    "user_account": process.user_account,
                    "is_hidden_window": process.is_hidden_window,
                    "is_service": process.is_service,
                    "loaded_dlls": process.loaded_dlls,
                    "privileges": process.privileges,
                },
                "risk_assessment": {
                    "risk_score": assessment.risk_score,
                    "risk_level": assessment.risk_level.value,
                    "explanation": assessment.explanation,
                    "triggered_rules": [
                        {
                            "rule_id": rule.rule_id,
                            "name": rule.name,
                            "description": rule.description,
                            "weight": rule.weight,
                            "evidence": rule.evidence,
                        }
                        for rule in assessment.triggered_rules
                    ]
                }
            }
            
            json_data["hooks"].append(hook_entry)
        
        # Write JSON file
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(json_data, f, indent=2, ensure_ascii=False)
        
        return str(filepath)
    
    def export_snapshot_csv(self,
                           snapshot_data: List[Dict],
                           filename: Optional[str] = None) -> str:
        """
        Export snapshot to CSV format.
        
        Args:
            snapshot_data: Snapshot data from monitor
            filename: Output filename (auto-generated if None)
            
        Returns:
            Path to exported file
        """
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"snapshot_{timestamp}.csv"
        
        filepath = self.output_dir / filename
        
        # Define CSV headers
        headers = [
            "HookID", "HookType", "PID", "ProcessName", "ProcessPath",
            "IsSigned", "UserAccount", "IsHidden", "IsService",
            "RiskScore", "RiskLevel", "TriggeredRules", "Explanation", "Timestamp"
        ]
        
        # Prepare rows
        rows = []
        for item in snapshot_data:
            hook: HookInfo = item["hook"]
            process: ProcessInfo = item["process"]
            assessment: RiskAssessment = item["assessment"]
            
            triggered_rules = "; ".join([
                f"{r.rule_id}:{r.name}" for r in assessment.triggered_rules
            ])
            
            row = [
                hook.hook_id,
                hook.hook_type,
                process.pid,
                process.name,
                process.path,
                process.is_signed,
                process.user_account,
                process.is_hidden_window,
                process.is_service,
                assessment.risk_score,
                assessment.risk_level.value,
                triggered_rules,
                assessment.explanation,
                hook.timestamp,
            ]
            
            rows.append(row)
        
        # Write CSV file
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(headers)
            writer.writerows(rows)
        
        return str(filepath)
    
    def export_events_json(self,
                          events: List[MonitorEvent],
                          filename: Optional[str] = None) -> str:
        """
        Export monitoring events to JSON.
        
        Args:
            events: List of monitoring events
            filename: Output filename (auto-generated if None)
            
        Returns:
            Path to exported file
        """
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"events_{timestamp}.json"
        
        filepath = self.output_dir / filename
        
        json_data = {
            "report_type": "events",
            "timestamp": datetime.now().isoformat(),
            "total_events": len(events),
            "events": []
        }
        
        for event in events:
            event_entry = {
                "event_type": event.event_type,
                "timestamp": event.timestamp,
                "details": event.details,
            }
            
            if event.hook_info:
                event_entry["hook"] = {
                    "hook_id": event.hook_info.hook_id,
                    "hook_type": event.hook_info.hook_type,
                    "owner_pid": event.hook_info.owner_pid,
                    "owner_process": event.hook_info.owner_process,
                }
            
            if event.process_info:
                event_entry["process"] = {
                    "pid": event.process_info.pid,
                    "name": event.process_info.name,
                    "path": event.process_info.path,
                    "is_signed": event.process_info.is_signed,
                }
            
            if event.risk_assessment:
                event_entry["risk"] = {
                    "score": event.risk_assessment.risk_score,
                    "level": event.risk_assessment.risk_level.value,
                    "explanation": event.risk_assessment.explanation,
                }
            
            json_data["events"].append(event_entry)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(json_data, f, indent=2, ensure_ascii=False)
        
        return str(filepath)
    
    def export_events_csv(self,
                         events: List[MonitorEvent],
                         filename: Optional[str] = None) -> str:
        """
        Export monitoring events to CSV.
        
        Args:
            events: List of monitoring events
            filename: Output filename (auto-generated if None)
            
        Returns:
            Path to exported file
        """
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"events_{timestamp}.csv"
        
        filepath = self.output_dir / filename
        
        headers = [
            "Timestamp", "EventType", "PID", "ProcessName",
            "HookType", "RiskScore", "RiskLevel", "Details"
        ]
        
        rows = []
        for event in events:
            row = [
                event.timestamp,
                event.event_type,
                event.process_info.pid if event.process_info else "",
                event.process_info.name if event.process_info else "",
                event.hook_info.hook_type if event.hook_info else "",
                event.risk_assessment.risk_score if event.risk_assessment else "",
                event.risk_assessment.risk_level.value if event.risk_assessment else "",
                event.details,
            ]
            rows.append(row)
        
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(headers)
            writer.writerows(rows)
        
        return str(filepath)
    
    def generate_summary_report(self,
                               snapshot_data: List[Dict],
                               events: List[MonitorEvent]) -> Dict[str, Any]:
        """
        Generate summary statistics report.
        
        Args:
            snapshot_data: Current snapshot
            events: Monitoring events
            
        Returns:
            Summary dictionary
        """
        from collections import Counter
        
        # Count risk levels
        risk_counts = Counter()
        for item in snapshot_data:
            assessment: RiskAssessment = item["assessment"]
            risk_counts[assessment.risk_level.value] += 1
        
        # Count event types
        event_counts = Counter(e.event_type for e in events)
        
        # Count processes
        process_names = set()
        for item in snapshot_data:
            process: ProcessInfo = item["process"]
            process_names.add(process.name)
        
        # High risk processes
        high_risk_procs = []
        for item in snapshot_data:
            assessment: RiskAssessment = item["assessment"]
            if assessment.risk_level.value == "HIGH":
                process: ProcessInfo = item["process"]
                high_risk_procs.append({
                    "pid": process.pid,
                    "name": process.name,
                    "path": process.path,
                    "score": assessment.risk_score,
                })
        
        summary = {
            "generated_at": datetime.now().isoformat(),
            "total_hooks": len(snapshot_data),
            "unique_processes": len(process_names),
            "total_events": len(events),
            "risk_distribution": dict(risk_counts),
            "event_types": dict(event_counts),
            "high_risk_processes": high_risk_procs,
        }
        
        return summary
    
    def export_summary_json(self,
                           snapshot_data: List[Dict],
                           events: List[MonitorEvent],
                           filename: Optional[str] = None) -> str:
        """
        Export summary report to JSON.
        
        Args:
            snapshot_data: Current snapshot
            events: Monitoring events
            filename: Output filename
            
        Returns:
            Path to exported file
        """
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"summary_{timestamp}.json"
        
        filepath = self.output_dir / filename
        
        summary = self.generate_summary_report(snapshot_data, events)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(summary, f, indent=2, ensure_ascii=False)
        
        return str(filepath)


class Logger:
    """Structured logger for hook detection events."""
    
    def __init__(self, log_file: str = "./logs/detection.log", max_size_mb: int = 10):
        """
        Initialize logger.
        
        Args:
            log_file: Path to log file
            max_size_mb: Maximum log file size before rotation
        """
        self.log_file = Path(log_file)
        self.log_file.parent.mkdir(parents=True, exist_ok=True)
        self.max_size = max_size_mb * 1024 * 1024  # Convert to bytes
        
        self._check_rotation()
    
    def _check_rotation(self):
        """Check if log rotation is needed."""
        if self.log_file.exists() and self.log_file.stat().st_size > self.max_size:
            # Rotate log
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            rotated_name = self.log_file.stem + f"_{timestamp}" + self.log_file.suffix
            rotated_path = self.log_file.parent / rotated_name
            
            self.log_file.rename(rotated_path)
    
    def log(self, level: str, message: str, **kwargs):
        """
        Write log entry.
        
        Args:
            level: Log level (INFO, WARNING, ERROR, etc.)
            message: Log message
            **kwargs: Additional structured data
        """
        entry = {
            "timestamp": datetime.now().isoformat(),
            "level": level,
            "message": message,
            **kwargs
        }
        
        with open(self.log_file, 'a', encoding='utf-8') as f:
            f.write(json.dumps(entry) + "\n")
        
        self._check_rotation()
    
    def log_event(self, event: MonitorEvent):
        """Log a monitoring event."""
        extra_data = {
            "event_type": event.event_type,
        }
        
        if event.hook_info:
            extra_data["hook_id"] = event.hook_info.hook_id
            extra_data["hook_type"] = event.hook_info.hook_type
            extra_data["owner_pid"] = event.hook_info.owner_pid
        
        if event.process_info:
            extra_data["process_name"] = event.process_info.name
            extra_data["process_path"] = event.process_info.path
        
        if event.risk_assessment:
            extra_data["risk_score"] = event.risk_assessment.risk_score
            extra_data["risk_level"] = event.risk_assessment.risk_level.value
        
        level = "WARNING" if (event.risk_assessment and 
                             event.risk_assessment.risk_level.value == "HIGH") else "INFO"
        
        self.log(level, event.details, **extra_data)


if __name__ == "__main__":
    # Test report generation
    from enumerator import MockEnumerator
    from heuristics import HeuristicEngine
    
    print("Testing Report Generator...\n")
    
    # Generate test data
    enum = MockEnumerator()
    heuristics = HeuristicEngine()
    
    snapshot_data = []
    hooks = enum.detect_hooks()
    
    for hook in hooks:
        proc = enum.get_process_info(hook.owner_pid)
        if proc:
            assessment = heuristics.analyze_hook(hook, proc)
            snapshot_data.append({
                "hook": hook,
                "process": proc,
                "assessment": assessment,
                "timestamp": datetime.now().isoformat()
            })
    
    # Test exports
    reporter = ReportGenerator(output_dir="./test_reports")
    
    # JSON export
    json_file = reporter.export_snapshot_json(snapshot_data)
    print(f"✓ JSON export: {json_file}")
    
    # CSV export
    csv_file = reporter.export_snapshot_csv(snapshot_data)
    print(f"✓ CSV export: {csv_file}")
    
    # Summary export
    summary_file = reporter.export_summary_json(snapshot_data, [])
    print(f"✓ Summary export: {summary_file}")
    
    # Test logger
    logger = Logger(log_file="./test_reports/test.log")
    logger.log("INFO", "Test log entry", test_data="example")
    print(f"✓ Logger test: ./test_reports/test.log")
    
    print("\nReport generation test complete!")
