#!/usr/bin/env python3
"""
Real-time Docker Compose build progress monitor.
Shows container status, service health, and build logs.
"""

import subprocess
import time
import sys
import json
from datetime import datetime
from collections import defaultdict

class BuildMonitor:
    def __init__(self):
        self.service_status = defaultdict(lambda: {"status": "pending", "ports": "", "logs": ""})
        self.colors = {
            "reset": "\033[0m",
            "bold": "\033[1m",
            "green": "\033[92m",
            "yellow": "\033[93m",
            "red": "\033[91m",
            "blue": "\033[94m",
            "cyan": "\033[96m",
        }

    def run_cmd(self, cmd, shell=True):
        """Run shell command and return output."""
        try:
            result = subprocess.run(
                cmd,
                shell=shell,
                capture_output=True,
                text=True,
                timeout=10
            )
            return result.stdout.strip()
        except Exception as e:
            return f"Error: {str(e)}"

    def get_container_status(self):
        """Get current container status from docker-compose."""
        output = self.run_cmd("docker-compose ps --format json")
        if not output or "Error" in output:
            return {}
        
        try:
            containers = json.loads(output)
            return {c["Service"]: c for c in containers}
        except Exception as e:
            return {"Error": str(e)}

    def get_service_logs(self, service, lines=5):
        """Get last N lines of service logs."""
        try:
            output = self.run_cmd(f"docker-compose logs --tail={lines} {service}")
            return output
        except Exception as e:
            return {"Error": str(e)}

    def print_header(self):
        """Print monitor header."""
        print("\033[2J\033[H")  # Clear screen
        print(f"{self.colors['bold']}{self.colors['cyan']}")
        print("╔" + "═" * 78 + "╗")
        print("║" + " " * 20 + "CORTEX SENTINEL BUILD MONITOR" + " " * 28 + "║")
        print("║" + " " * 78 + "║")
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"║ {timestamp}" + " " * (78 - len(timestamp) - 1) + "║")
        print("╚" + "═" * 78 + "╝")
        print(f"{self.colors['reset']}")

    def print_service(self, name, status):
        """Print individual service status."""
        status_text = status.get("Status", "unknown")
        ports = status.get("Ports", "—")
        
        # Determine color based on status
        if "running" in status_text.lower():
            color = self.colors['green']
            icon = "✓"
        elif "building" in status_text.lower() or "pulling" in status_text.lower():
            color = self.colors['yellow']
            icon = "↻"
        elif "exited" in status_text.lower() or "created" in status_text.lower():
            color = self.colors['yellow']
            icon = "⏸"
        else:
            color = self.colors['red']
            icon = "✗"
        
        status_display = f"{color}{icon} {status_text[:30]:<30}{self.colors['reset']}"
        ports_display = f"{self.colors['blue']}{ports[:35]:<35}{self.colors['reset']}"
        
        print(f"  {name:<20} │ {status_display} │ {ports_display}")

    def print_services(self, containers):
        """Print all services table."""
        services_order = [
            "redis",
            "ollama",
            "scan_worker",
            "report_worker",
            "memory_worker",
            "scoring_worker",
            "api",
            "logging_worker",
            "dashboard"
        ]
        
        print(f"\n{self.colors['bold']}SERVICE STATUS:{self.colors['reset']}")
        print("┌" + "─" * 78 + "┐")
        print(f"│ {'Service':<20} │ {'Status':<32} │ {'Ports':<23} │")
        print("├" + "─" * 78 + "┤")
        
        for service in services_order:
            if service in containers:
                self.print_service(service, containers[service])
        
        print("└" + "─" * 78 + "┘")

    def print_logs(self, service, limit=3):
        """Print service logs."""
        logs = self.get_service_logs(service, lines=limit)
        if logs:
            print(f"\n{self.colors['bold']}{service.upper()} LOGS:{self.colors['reset']}")
            print("┌" + "─" * 78 + "┐")
            for line in logs.split('\n')[-limit:]:
                if line:
                    # Truncate long lines
                    if len(line) > 76:
                        line = line[:73] + "..."
                    print(f"│ {line:<76} │")
            print("└" + "─" * 78 + "┘")

    def get_disk_space(self):
        """Get Docker disk usage."""
        output = self.run_cmd("docker system df")
        if not output or "Error" in output:
            return None
        return output

    def print_system_info(self):
        """Print Docker system info."""
        print(f"\n{self.colors['bold']}DOCKER SYSTEM INFO:{self.colors['reset']}")
        print("┌" + "─" * 78 + "┐")
        
        # Show disk space
        disk_info = self.get_disk_space()
        if disk_info:
            lines = disk_info.split('\n')[:10]
            for line in lines:
                if line:
                    if len(line) > 76:
                        line = line[:73] + "..."
                    print(f"│ {line:<76} │")
        
        print("└" + "─" * 78 + "┘")

    def get_build_progress(self):
        """Estimate build progress."""
        containers = self.get_container_status()
        
        states = {
            "pending": 0,
            "building": 0,
            "running": 0,
            "exited": 0,
            "error": 0
        }
        
        for service, status in containers.items():
            status_text = status.get("Status", "").lower()
            if "running" in status_text:
                states["running"] += 1
            elif "exited" in status_text:
                states["exited"] += 1
            elif "building" in status_text or "pulling" in status_text:
                states["building"] += 1
            else:
                states["pending"] += 1
        
        total = sum(states.values()) or 1
        progress = int((states["running"] / total) * 100)
        
        return progress, states

    def print_progress_bar(self):
        """Print overall progress bar."""
        progress, states = self.get_build_progress()
        
        print(f"\n{self.colors['bold']}BUILD PROGRESS:{self.colors['reset']}")
        print("┌" + "─" * 78 + "┐")
        
        bar_length = 50
        filled = int((progress / 100) * bar_length)
        bar = "█" * filled + "░" * (bar_length - filled)
        
        print(f"│ [{bar}] {progress:>3}%")
        print("│")
        print(f"│ Running: {self.colors['green']}{states['running']}{self.colors['reset']} │ " +
              f"Building: {self.colors['yellow']}{states['building']}{self.colors['reset']} │ " +
              f"Exited: {states['exited']} │ " +
              f"Pending: {states['pending']}")
        
        print("└" + "─" * 78 + "┘")

    def print_instructions(self):
        """Print helpful instructions."""
        print(f"\n{self.colors['bold']}INSTRUCTIONS:{self.colors['reset']}")
        print("┌" + "─" * 78 + "┐")
        print("│ Press Ctrl+C to stop monitoring                                          │")
        print("│ Check logs: docker-compose logs <service>                                │")
        print("│ Follow logs: docker-compose logs -f <service>                            │")
        print("│ Once all services show ✓, system is ready!                               │")
        print("└" + "─" * 78 + "┘")

    def run(self, refresh_interval=5):
        """Main monitor loop."""
        try:
            while True:
                self.print_header()
                containers = self.get_container_status()
                
                if containers:
                    self.print_services(containers)
                    self.print_progress_bar()
                    
                    # Show logs from active services
                    for service in ["ollama", "redis", "api"]:
                        if service in containers:
                            self.print_logs(service, limit=2)
                else:
                    print(f"\n{self.colors['yellow']}⚠ No containers found yet. Still initializing...{self.colors['reset']}")
                
                self.print_system_info()
                self.print_instructions()
                
                print(f"\n{self.colors['cyan']}Next refresh in {refresh_interval}s... (Ctrl+C to exit){self.colors['reset']}")
                time.sleep(refresh_interval)
                
        except KeyboardInterrupt:
            print(f"\n\n{self.colors['bold']}{self.colors['green']}Build monitor stopped.{self.colors['reset']}")
            print("Run 'docker-compose logs' to see full logs.")
            sys.exit(0)
        except Exception as e:
            print(f"\n{self.colors['red']}Error: {str(e)}{self.colors['reset']}")
            sys.exit(1)

if __name__ == "__main__":
    monitor = BuildMonitor()
    monitor.run(refresh_interval=5)
