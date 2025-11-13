"""
Heuristics Module - Behavioral analysis and risk scoring for hook detection.

This module implements detection rules and explainable risk scoring.
"""

from typing import List, Dict, Any, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
from enumerator import ProcessInfo, HookInfo


class RiskLevel(Enum):
    """Risk classification levels."""
    LOW = "LOW"  # 0-30 points
    MEDIUM = "MEDIUM"  # 31-60 points
    HIGH = "HIGH"  # 61+ points
    UNKNOWN = "UNKNOWN"


@dataclass
class RiskRule:
    """Individual risk detection rule."""
    rule_id: str
    name: str
    description: str
    weight: int  # Points to add if triggered
    triggered: bool = False
    evidence: str = ""


@dataclass
class RiskAssessment:
    """Complete risk assessment result."""
    pid: int
    process_name: str
    risk_score: int
    risk_level: RiskLevel
    triggered_rules: List[RiskRule]
    explanation: str
    timestamp: str


class HeuristicEngine:
    """
    Behavioral heuristics engine for detecting suspicious hooks.
    
    Implements multiple detection rules with configurable weights.
    """
    
    def __init__(self, sensitivity: str = "medium"):
        """
        Initialize heuristic engine.
        
        Args:
            sensitivity: Detection sensitivity (low/medium/high)
        """
        self.sensitivity = sensitivity
        self.rules = self._initialize_rules()
        
        # Adjust weights based on sensitivity
        if sensitivity == "high":
            for rule in self.rules.values():
                rule.weight = int(rule.weight * 1.3)
        elif sensitivity == "low":
            for rule in self.rules.values():
                rule.weight = int(rule.weight * 0.7)
    
    def _initialize_rules(self) -> Dict[str, RiskRule]:
        """Initialize detection rules with weights."""
        return {
            "unsigned_binary": RiskRule(
                rule_id="R001",
                name="Unsigned Binary",
                description="Executable lacks valid digital signature",
                weight=25
            ),
            "hidden_window": RiskRule(
                rule_id="R002",
                name="Hidden Window",
                description="Process has no visible windows (may be hiding)",
                weight=20
            ),
            "unusual_path": RiskRule(
                rule_id="R003",
                name="Unusual Path",
                description="Executable located in suspicious directory",
                weight=30
            ),
            "elevated_privileges": RiskRule(
                rule_id="R004",
                name="Unexpected Elevation",
                description="Process has elevated privileges without clear reason",
                weight=15
            ),
            "suspicious_dll": RiskRule(
                rule_id="R005",
                name="Suspicious DLL",
                description="Process loaded unusual or injected DLLs",
                weight=25
            ),
            "orphan_process": RiskRule(
                rule_id="R006",
                name="Orphan Process",
                description="Parent process no longer exists",
                weight=10
            ),
            "temp_location": RiskRule(
                rule_id="R007",
                name="Temp Directory Execution",
                description="Executable running from temporary directory",
                weight=20
            ),
            "name_spoofing": RiskRule(
                rule_id="R008",
                name="Name Spoofing",
                description="Process name mimics system process but path differs",
                weight=35
            ),
            "service_anomaly": RiskRule(
                rule_id="R009",
                name="Unknown Service",
                description="Marked as service but not recognized",
                weight=15
            ),
            "multiple_hooks": RiskRule(
                rule_id="R010",
                name="Multiple Hooks",
                description="Process has registered multiple keyboard hooks",
                weight=20
            ),
        }
    
    def analyze_process(self, proc_info: ProcessInfo, hook_count: int = 1) -> RiskAssessment:
        """
        Analyze a process and calculate risk score.
        
        Args:
            proc_info: Process metadata
            hook_count: Number of hooks from this process
            
        Returns:
            RiskAssessment with score and explanation
        """
        from datetime import datetime
        
        # Reset rules
        for rule in self.rules.values():
            rule.triggered = False
            rule.evidence = ""
        
        triggered = []
        score = 0
        
        # Apply each heuristic
        self._check_unsigned_binary(proc_info, triggered)
        self._check_hidden_window(proc_info, triggered)
        self._check_unusual_path(proc_info, triggered)
        self._check_elevated_privileges(proc_info, triggered)
        self._check_suspicious_dlls(proc_info, triggered)
        self._check_orphan_process(proc_info, triggered)
        self._check_temp_location(proc_info, triggered)
        self._check_name_spoofing(proc_info, triggered)
        self._check_service_anomaly(proc_info, triggered)
        self._check_multiple_hooks(hook_count, triggered)
        
        # Calculate total score
        score = sum(rule.weight for rule in triggered)
        
        # Determine risk level
        if score >= 61:
            level = RiskLevel.HIGH
        elif score >= 31:
            level = RiskLevel.MEDIUM
        else:
            level = RiskLevel.LOW
        
        # Generate explanation
        explanation = self._generate_explanation(triggered, score)
        
        return RiskAssessment(
            pid=proc_info.pid,
            process_name=proc_info.name,
            risk_score=score,
            risk_level=level,
            triggered_rules=triggered,
            explanation=explanation,
            timestamp=datetime.now().isoformat()
        )
    
    def _check_unsigned_binary(self, proc: ProcessInfo, triggered: List[RiskRule]):
        """Check if binary is unsigned."""
        if not proc.is_signed:
            rule = self.rules["unsigned_binary"]
            rule.triggered = True
            rule.evidence = f"No valid signature found for {proc.path}"
            triggered.append(rule)
    
    def _check_hidden_window(self, proc: ProcessInfo, triggered: List[RiskRule]):
        """Check if process has hidden windows."""
        if proc.is_hidden_window and not proc.is_service:
            rule = self.rules["hidden_window"]
            rule.triggered = True
            rule.evidence = "Process runs without visible windows"
            triggered.append(rule)
    
    def _check_unusual_path(self, proc: ProcessInfo, triggered: List[RiskRule]):
        """Check if executable is in unusual location."""
        suspicious_paths = [
            ":\\users\\",
            ":\\temp\\",
            ":\\downloads\\",
            ":\\appdata\\roaming\\",
        ]
        
        path_lower = proc.path.lower()
        
        # Skip system paths
        if "\\windows\\" in path_lower or "\\program files" in path_lower:
            return
        
        for sus_path in suspicious_paths:
            if sus_path in path_lower:
                rule = self.rules["unusual_path"]
                rule.triggered = True
                rule.evidence = f"Executing from {proc.path}"
                triggered.append(rule)
                break
    
    def _check_elevated_privileges(self, proc: ProcessInfo, triggered: List[RiskRule]):
        """Check for unexpected privilege elevation."""
        if "ELEVATED" in proc.privileges and not proc.is_service:
            # Check if it's a known system process that should be elevated
            system_elevated = ["taskmgr.exe", "regedit.exe", "cmd.exe", "powershell.exe"]
            
            if proc.name.lower() not in system_elevated:
                rule = self.rules["elevated_privileges"]
                rule.triggered = True
                rule.evidence = f"Process has elevated privileges: {', '.join(proc.privileges)}"
                triggered.append(rule)
    
    def _check_suspicious_dlls(self, proc: ProcessInfo, triggered: List[RiskRule]):
        """Check for suspicious loaded DLLs."""
        suspicious_dll_patterns = [
            "hook", "inject", "keylog", "capture", "spy",
            "monitor", "intercept", "suspicious"
        ]
        
        for dll in proc.loaded_dlls:
            dll_lower = dll.lower()
            for pattern in suspicious_dll_patterns:
                if pattern in dll_lower:
                    rule = self.rules["suspicious_dll"]
                    rule.triggered = True
                    rule.evidence = f"Loaded suspicious DLL: {dll}"
                    triggered.append(rule)
                    return
    
    def _check_orphan_process(self, proc: ProcessInfo, triggered: List[RiskRule]):
        """Check if parent process no longer exists."""
        # This would require checking if parent PID exists
        # Simplified check: if parent is 0 or very low PID, might be orphaned
        if proc.parent_pid > 0 and proc.parent_pid < 4 and proc.pid > 100:
            rule = self.rules["orphan_process"]
            rule.triggered = True
            rule.evidence = f"Parent PID {proc.parent_pid} likely terminated"
            triggered.append(rule)
    
    def _check_temp_location(self, proc: ProcessInfo, triggered: List[RiskRule]):
        """Check if running from temp directory."""
        temp_paths = ["\\temp\\", "\\tmp\\", "\\appdata\\local\\temp"]
        
        path_lower = proc.path.lower()
        for temp_path in temp_paths:
            if temp_path in path_lower:
                rule = self.rules["temp_location"]
                rule.triggered = True
                rule.evidence = f"Running from temp: {proc.path}"
                triggered.append(rule)
                break
    
    def _check_name_spoofing(self, proc: ProcessInfo, triggered: List[RiskRule]):
        """Check for process name spoofing."""
        # System processes with expected paths
        system_procs = {
            "system": "\\windows\\system32\\ntoskrnl.exe",
            "svchost.exe": "\\windows\\system32\\svchost.exe",
            "explorer.exe": "\\windows\\explorer.exe",
            "lsass.exe": "\\windows\\system32\\lsass.exe",
            "csrss.exe": "\\windows\\system32\\csrss.exe",
            "winlogon.exe": "\\windows\\system32\\winlogon.exe",
        }
        
        name_lower = proc.name.lower()
        if name_lower in system_procs:
            expected_path = system_procs[name_lower]
            if expected_path not in proc.path.lower():
                rule = self.rules["name_spoofing"]
                rule.triggered = True
                rule.evidence = f"{proc.name} running from unexpected path: {proc.path}"
                triggered.append(rule)
    
    def _check_service_anomaly(self, proc: ProcessInfo, triggered: List[RiskRule]):
        """Check for unknown service processes."""
        # This is simplified - real implementation would check against
        # known service list
        if proc.is_service and not proc.is_signed:
            rule = self.rules["service_anomaly"]
            rule.triggered = True
            rule.evidence = f"Unsigned service: {proc.name}"
            triggered.append(rule)
    
    def _check_multiple_hooks(self, hook_count: int, triggered: List[RiskRule]):
        """Check if process has multiple hooks."""
        if hook_count > 2:
            rule = self.rules["multiple_hooks"]
            rule.triggered = True
            rule.evidence = f"Process registered {hook_count} hooks"
            triggered.append(rule)
    
    def _generate_explanation(self, triggered: List[RiskRule], score: int) -> str:
        """
        Generate human-readable explanation of risk score.
        
        Args:
            triggered: List of triggered rules
            score: Total risk score
            
        Returns:
            Explanation string
        """
        if not triggered:
            return f"No suspicious indicators detected. Score: {score}/100 (LOW risk)"
        
        explanations = [f"{rule.name} (+{rule.weight})" for rule in triggered]
        summary = ", ".join(explanations)
        
        return f"Score: {score}/100. Triggered: {summary}"
    
    def analyze_hook(self, hook: HookInfo, proc_info: ProcessInfo) -> RiskAssessment:
        """
        Analyze a specific hook with its owner process.
        
        Args:
            hook: Hook information
            proc_info: Owner process information
            
        Returns:
            RiskAssessment
        """
        return self.analyze_process(proc_info, hook_count=1)
    
    def get_rules_summary(self) -> List[Dict[str, Any]]:
        """
        Get summary of all detection rules.
        
        Returns:
            List of rule dictionaries
        """
        return [
            {
                "id": rule.rule_id,
                "name": rule.name,
                "description": rule.description,
                "weight": rule.weight,
            }
            for rule in self.rules.values()
        ]


def classify_risk(score: int) -> RiskLevel:
    """
    Classify numeric score into risk level.
    
    Args:
        score: Risk score (0-100+)
        
    Returns:
        RiskLevel enum
    """
    if score >= 61:
        return RiskLevel.HIGH
    elif score >= 31:
        return RiskLevel.MEDIUM
    elif score >= 0:
        return RiskLevel.LOW
    else:
        return RiskLevel.UNKNOWN


def get_risk_color(level: RiskLevel) -> str:
    """
    Get color code for risk level.
    
    Args:
        level: Risk level
        
    Returns:
        Color name for UI
    """
    colors = {
        RiskLevel.HIGH: "red",
        RiskLevel.MEDIUM: "yellow",
        RiskLevel.LOW: "green",
        RiskLevel.UNKNOWN: "white",
    }
    return colors.get(level, "white")


if __name__ == "__main__":
    # Test heuristics engine
    from enumerator import MockEnumerator
    
    print("Testing Heuristic Engine...\n")
    
    engine = HeuristicEngine(sensitivity="medium")
    enum = MockEnumerator()
    
    # Test with mock processes
    pids = enum.enumerate_processes()
    
    for pid in pids:
        proc = enum.get_process_info(pid)
        if proc:
            assessment = engine.analyze_process(proc)
            
            print(f"\n{'='*70}")
            print(f"Process: {proc.name} (PID {pid})")
            print(f"Risk Score: {assessment.risk_score}/100 ({assessment.risk_level.value})")
            print(f"Explanation: {assessment.explanation}")
            
            if assessment.triggered_rules:
                print(f"\nTriggered Rules:")
                for rule in assessment.triggered_rules:
                    print(f"  [{rule.rule_id}] {rule.name} (+{rule.weight} points)")
                    print(f"      {rule.evidence}")
    
    # Print rules summary
    print(f"\n\n{'='*70}")
    print("Detection Rules Summary:")
    print(f"{'='*70}")
    
    for rule_info in engine.get_rules_summary():
        print(f"[{rule_info['id']}] {rule_info['name']} (Weight: {rule_info['weight']})")
        print(f"    {rule_info['description']}")
        print()
