# intelligence/usage_tracker.py
# ──────────────────────────────────────────────────────────────────────────────
# ENHANCED USAGE TRACKER — Comprehensive cost tracking and budget management
# with real-time monitoring, forecasting, and enterprise features
# ──────────────────────────────────────────────────────────────────────────────

import time
import logging
import threading
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
from collections import defaultdict, deque
import json

logger = logging.getLogger(__name__)

class UsageTracker:
    def __init__(self, max_budget_usd: float = 2.00, config: Dict = None):
        self.start_time = time.time()
        self.max_budget = max_budget_usd
        self.is_active = True
        self.lock = threading.RLock()
        
        # Configuration with defaults
        self.config = {
            "alert_threshold": 0.8,  # 80% budget usage
            "refresh_interval": 60,  # 60 seconds
            "retention_period": 24 * 3600,  # 24 hours
            "enable_forecasting": True,
            "cost_optimization": True,
            ** (config or {})
        }
        
        # Enhanced pricing model
        self.pricing_model = {
            "ai_validation": {
                "base_cost": 0.00001,
                "per_token": 0.000125 / 1000,  # $0.000125 per 1K tokens
                "min_tokens": 100
            },
            "request": {
                "base_cost": 0.000005,
                "size_factor": 0.0000001  # $0.0000001 per byte
            },
            "waf_bypass": {
                "cost": 0.00002,
                "complexity_multiplier": 1.5
            },
            "oast_poll": {
                "cost": 0.00001
            },
            "attack_planning": {
                "base_cost": 0.00003,
                "per_node": 0.000001
            },
            "report_generation": {
                "base_cost": 0.00005,
                "per_finding": 0.000002
            }
        }
        
        # Comprehensive statistics
        self.stats = {
            "total_requests": 0,
            "ai_validations": 0,
            "waf_bypasses": 0,
            "oast_polls": 0,
            "attack_plans": 0,
            "reports_generated": 0,
            "estimated_cost_usd": 0.0,
            "budget_remaining": max_budget_usd,
            "budget_utilization": 0.0,
            "request_rate": 0.0,
            "cost_rate": 0.0
        }
        
        # Detailed cost breakdown
        self.cost_breakdown = {
            "ai_services": 0.0,
            "network_requests": 0.0,
            "waf_evasion": 0.0,
            "oast_services": 0.0,
            "planning_services": 0.0,
            "reporting_services": 0.0
        }
        
        # Time-series data for forecasting
        self.time_series = {
            "costs": deque(maxlen=1000),
            "requests": deque(maxlen=1000),
            "timestamps": deque(maxlen=1000)
        }
        
        # Alert system
        self.alerts_triggered = []
        self.last_alert_time = 0
        
        # Start monitoring thread
        self._start_monitoring()

    def _start_monitoring(self):
        """Start background monitoring thread"""
        def monitor_loop():
            while True:
                try:
                    self._update_rates()
                    self._check_budget()
                    self._check_alerts()
                    time.sleep(self.config["refresh_interval"])
                except Exception as e:
                    logger.error(f"Monitoring thread error: {e}")
                    time.sleep(60)  # Wait before retry
        
        thread = threading.Thread(target=monitor_loop, daemon=True)
        thread.start()

    def _update_rates(self):
        """Update rate calculations"""
        with self.lock:
            elapsed = time.time() - self.start_time
            if elapsed > 0:
                self.stats["request_rate"] = self.stats["total_requests"] / elapsed
                self.stats["cost_rate"] = self.stats["estimated_cost_usd"] / elapsed

    def _check_budget(self):
        """Check budget and update kill switch"""
        with self.lock:
            self.stats["budget_remaining"] = self.max_budget - self.stats["estimated_cost_usd"]
            self.stats["budget_utilization"] = (self.stats["estimated_cost_usd"] / self.max_budget) * 100
            
            if self.stats["estimated_cost_usd"] >= self.max_budget and self.is_active:
                self.is_active = False
                logger.critical(f"!!! KILL SWITCH TRIGGERED: Budget of ${self.max_budget} reached !!!")
                self._trigger_alert("budget_exceeded", f"Budget exceeded: ${self.stats['estimated_cost_usd']:.6f}")

    def _check_alerts(self):
        """Check and trigger alerts"""
        current_time = time.time()
        
        # Budget threshold alert
        if (self.stats["budget_utilization"] >= self.config["alert_threshold"] * 100 and 
            current_time - self.last_alert_time > 300):  # 5 minute cooldown
            self._trigger_alert("budget_warning", 
                               f"Budget {self.stats['budget_utilization']:.1f}% utilized")
            self.last_alert_time = current_time
        
        # High usage rate alert
        if self.stats["cost_rate"] * 3600 > self.max_budget * 0.1:  # >10% per hour
            self._trigger_alert("high_usage_rate", 
                               f"High usage rate: ${self.stats['cost_rate'] * 3600:.4f}/hour")

    def _trigger_alert(self, alert_type: str, message: str):
        """Trigger an alert"""
        alert = {
            "type": alert_type,
            "timestamp": datetime.now().isoformat(),
            "message": message,
            "stats": self.stats.copy()
        }
        self.alerts_triggered.append(alert)
        logger.warning(f"ALERT: {message}")

    def log_request(self, request_size: int = 0, endpoint: str = None):
        """Log a general request"""
        if not self.is_active:
            return False
            
        with self.lock:
            cost = (self.pricing_model["request"]["base_cost"] + 
                   request_size * self.pricing_model["request"]["size_factor"])
            
            self.stats["total_requests"] += 1
            self.stats["estimated_cost_usd"] += cost
            self.cost_breakdown["network_requests"] += cost
            
            # Record time-series data
            self._record_data_point(cost, 1)
            
            self._check_budget()
            return self.is_active

    def log_ai_usage(self, input_chars: int, output_chars: int, service_type: str = "ai_validation"):
        """Log AI service usage with detailed costing"""
        if not self.is_active:
            return False
            
        with self.lock:
            # Calculate token-based cost
            tokens = max((input_chars + output_chars) / 4, self.pricing_model[service_type]["min_tokens"])
            cost = (self.pricing_model[service_type]["base_cost"] + 
                   tokens * self.pricing_model[service_type]["per_token"])
            
            self.stats["ai_validations"] += 1
            self.stats["estimated_cost_usd"] += cost
            self.cost_breakdown["ai_services"] += cost
            
            # Record time-series data
            self._record_data_point(cost, 1)
            
            self._check_budget()
            return self.is_active

    def log_waf_bypass(self, complexity: str = "medium"):
        """Log WAF bypass activity"""
        if not self.is_active:
            return False
            
        with self.lock:
            multiplier = {"low": 1.0, "medium": 1.5, "high": 2.0}.get(complexity, 1.5)
            cost = self.pricing_model["waf_bypass"]["cost"] * multiplier
            
            self.stats["waf_bypasses"] += 1
            self.stats["estimated_cost_usd"] += cost
            self.cost_breakdown["waf_evasion"] += cost
            
            self._record_data_point(cost, 0)  # 0 requests for rate calculation
            
            self._check_budget()
            return self.is_active

    def log_oast_poll(self):
        """Log OAST polling activity"""
        if not self.is_active:
            return False
            
        with self.lock:
            cost = self.pricing_model["oast_poll"]["cost"]
            
            self.stats["oast_polls"] += 1
            self.stats["estimated_cost_usd"] += cost
            self.cost_breakdown["oast_services"] += cost
            
            self._record_data_point(cost, 0)
            
            self._check_budget()
            return self.is_active

    def log_attack_planning(self, node_count: int = 0):
        """Log attack planning activity"""
        if not self.is_active:
            return False
            
        with self.lock:
            cost = (self.pricing_model["attack_planning"]["base_cost"] + 
                   node_count * self.pricing_model["attack_planning"]["per_node"])
            
            self.stats["attack_plans"] += 1
            self.stats["estimated_cost_usd"] += cost
            self.cost_breakdown["planning_services"] += cost
            
            self._record_data_point(cost, 0)
            
            self._check_budget()
            return self.is_active

    def log_report_generation(self, finding_count: int = 0):
        """Log report generation activity"""
        if not self.is_active:
            return False
            
        with self.lock:
            cost = (self.pricing_model["report_generation"]["base_cost"] + 
                   finding_count * self.pricing_model["report_generation"]["per_finding"])
            
            self.stats["reports_generated"] += 1
            self.stats["estimated_cost_usd"] += cost
            self.cost_breakdown["reporting_services"] += cost
            
            self._record_data_point(cost, 0)
            
            self._check_budget()
            return self.is_active

    def _record_data_point(self, cost: float, requests: int):
        """Record data point for time-series analysis"""
        current_time = time.time()
        self.time_series["costs"].append((current_time, cost))
        self.time_series["requests"].append((current_time, requests))
        self.time_series["timestamps"].append(current_time)
        
        # Clean old data
        cutoff = current_time - self.config["retention_period"]
        while self.time_series["timestamps"] and self.time_series["timestamps"][0] < cutoff:
            self.time_series["costs"].popleft()
            self.time_series["requests"].popleft()
            self.time_series["timestamps"].popleft()

    def forecast_usage(self, hours: int = 24) -> Dict:
        """Forecast usage based on current trends"""
        if not self.time_series["costs"]:
            return {"estimated_cost": 0.0, "budget_exhaustion": None}
        
        with self.lock:
            # Calculate average cost rate
            recent_costs = [cost for ts, cost in self.time_series["costs"] 
                          if ts > time.time() - 3600]  # Last hour
            if not recent_costs:
                recent_costs = [cost for _, cost in self.time_series["costs"]]
            
            avg_hourly_cost = sum(recent_costs) / len(recent_costs) * 3600
            
            # Forecast
            forecast_cost = avg_hourly_cost * hours
            total_forecast = self.stats["estimated_cost_usd"] + forecast_cost
            
            # Calculate exhaustion time
            if avg_hourly_cost > 0:
                hours_remaining = (self.max_budget - self.stats["estimated_cost_usd"]) / avg_hourly_cost
                exhaustion_time = datetime.now() + timedelta(hours=hours_remaining)
            else:
                exhaustion_time = None
            
            return {
                "estimated_cost": round(total_forecast, 6),
                "budget_exhaustion": exhaustion_time.isoformat() if exhaustion_time else None,
                "hourly_rate": round(avg_hourly_cost, 6),
                "confidence": min(len(recent_costs) / 10, 1.0)  # Based on data points
            }

    def get_optimization_suggestions(self) -> List[Dict]:
        """Get cost optimization suggestions"""
        suggestions = []
        
        with self.lock:
            # AI cost optimization
            ai_percentage = (self.cost_breakdown["ai_services"] / 
                           max(self.stats["estimated_cost_usd"], 0.000001)) * 100
            if ai_percentage > 50:
                suggestions.append({
                    "category": "ai_services",
                    "issue": f"AI services consume {ai_percentage:.1f}% of budget",
                    "recommendation": "Optimize AI prompt efficiency and cache responses",
                    "potential_savings": "30-50%"
                })
            
            # Request optimization
            if self.stats["total_requests"] > 1000 and self.cost_breakdown["network_requests"] > 0.001:
                suggestions.append({
                    "category": "network_requests",
                    "issue": "High network request volume",
                    "recommendation": "Implement request batching and caching",
                    "potential_savings": "40-60%"
                })
            
            # WAF bypass optimization
            if self.stats["waf_bypasses"] > 20:
                suggestions.append({
                    "category": "waf_evasion",
                    "issue": "Frequent WAF bypass attempts",
                    "recommendation": "Use more efficient payloads and rotation strategies",
                    "potential_savings": "25-40%"
                })
        
        return suggestions

    def get_detailed_metrics(self) -> Dict:
        """Get comprehensive metrics"""
        with self.lock:
            metrics = self.stats.copy()
            metrics.update({
                "cost_breakdown": self.cost_breakdown.copy(),
                "is_active": self.is_active,
                "uptime_seconds": round(time.time() - self.start_time, 2),
                "alerts_triggered": len(self.alerts_triggered),
                "time_series_stats": {
                    "data_points": len(self.time_series["costs"]),
                    "time_range_seconds": (self.time_series["timestamps"][-1] - self.time_series["timestamps"][0] 
                                         if self.time_series["timestamps"] else 0)
                }
            })
            
            # Add forecasting
            if self.config["enable_forecasting"]:
                metrics["forecast"] = self.forecast_usage(24)
            
            # Add optimizations
            if self.config["cost_optimization"]:
                metrics["optimization_suggestions"] = self.get_optimization_suggestions()
            
            return metrics

    def export_report(self, format: str = "json") -> str:
        """Export usage report"""
        metrics = self.get_detailed_metrics()
        
        if format.lower() == "json":
            return json.dumps(metrics, indent=2)
        elif format.lower() == "text":
            return self._format_text_report(metrics)
        else:
            raise ValueError(f"Unsupported format: {format}")

    def _format_text_report(self, metrics: Dict) -> str:
        """Format metrics as text report"""
        report = [
            "SECURITY SCAN USAGE REPORT",
            "=" * 50,
            f"Generated: {datetime.now().isoformat()}",
            f"Total Cost: ${metrics['estimated_cost_usd']:.6f}",
            f"Budget: ${metrics['budget_remaining']:.6f} remaining of ${self.max_budget:.2f}",
            f"Utilization: {metrics['budget_utilization']:.1f}%",
            f"Active: {metrics['is_active']}",
            "",
            "BREAKDOWN:",
            f"  AI Services: ${metrics['cost_breakdown']['ai_services']:.6f}",
            f"  Network: ${metrics['cost_breakdown']['network_requests']:.6f}",
            f"  WAF Bypasses: ${metrics['cost_breakdown']['waf_evasion']:.6f}",
            f"  OAST: ${metrics['cost_breakdown']['oast_services']:.6f}",
            "",
            "ACTIVITY:",
            f"  Total Requests: {metrics['total_requests']}",
            f"  AI Validations: {metrics['ai_validations']}",
            f"  WAF Bypasses: {metrics['waf_bypasses']}",
            f"  Attack Plans: {metrics['attack_plans']}",
            f"  Reports: {metrics['reports_generated']}",
            ""
        ]
        
        # Add alerts
        if metrics['alerts_triggered'] > 0:
            report.append(f"ALERTS: {metrics['alerts_triggered']} triggered")
        
        return "\n".join(report)

    def reset(self, new_budget: Optional[float] = None):
        """Reset tracker with optional new budget"""
        with self.lock:
            if new_budget is not None:
                self.max_budget = new_budget
            
            self.start_time = time.time()
            self.is_active = True
            
            # Reset statistics
            for key in self.stats:
                if key != "max_budget":
                    self.stats[key] = 0 if isinstance(self.stats[key], (int, float)) else 0.0
            
            for key in self.cost_breakdown:
                self.cost_breakdown[key] = 0.0
            
            self.time_series = {"costs": deque(), "requests": deque(), "timestamps": deque()}
            self.alerts_triggered = []
            
            logger.info(f"Usage tracker reset with budget: ${self.max_budget:.2f}")

# Global instance for easy access
usage_tracker = UsageTracker()
