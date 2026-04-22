#!/usr/bin/env python3
"""
QUICK START: Tools Reference for Cortex Sentinel

This file lists all new tools and how to use them.
"""

print("""
╔════════════════════════════════════════════════════════════════════════════╗
║                  CORTEX SENTINEL - QUICK START GUIDE                       ║
╚════════════════════════════════════════════════════════════════════════════╝

================================================================================
                            📊 BUILD MONITOR
================================================================================

FILE: monitor_build.py

DESCRIPTION:
  Real-time Docker Compose build progress dashboard.
  Shows container status, service health, logs, and disk usage.

USAGE:
  python monitor_build.py

FEATURES:
  • Live container status (running, building, exited)
  • Port mappings and service health
  • Real-time service logs (last 2 lines)
  • Build progress bar with stage breakdown
  • Docker disk usage
  • Auto-refresh every 5 seconds
  • Press Ctrl+C to exit

EXAMPLE OUTPUT:
  ┌────────────────────────────────────────────────────────────────────────┐
  │ CORTEX SENTINEL BUILD MONITOR                                          │
  │ 2024-01-15 14:32:10                                                    │
  ├────────────────────────────────────────────────────────────────────────┤
  │ SERVICE STATUS:                                                        │
  │  redis         ✓ running        0.0.0.0:6379->6379/tcp                │
  │  ollama        ↻ pulling image  0.0.0.0:11434->11434/tcp              │
  │  api           ⏸ created        0.0.0.0:8000->8000/tcp                │
  │  ...                                                                   │
  │ BUILD PROGRESS: [████████░░░░░░░░░░░░░░░░░░░░░░░░░░░░]  35%           │
  │  Running: 2 │ Building: 3 │ Exited: 0 │ Pending: 4                   │
  └────────────────────────────────────────────────────────────────────────┘

================================================================================
                           🔍 DIAGNOSIS TOOL
================================================================================

FILE: diagnose.py

DESCRIPTION:
  Check Redis connectivity and job log status.
  Helps debug "job exists but no logs" issues.

USAGE:
  python diagnose.py              # List all jobs
  python diagnose.py job_id_here  # Check specific job

FEATURES:
  • Verify Redis is accessible
  • List all jobs in Redis
  • Show job log count
  • Display last 10 logs per job
  • Formatted output with ✓/✗ indicators

EXAMPLE OUTPUT:
  ════════════════════════════════════════════════════════════════
  Cortex Sentinel Diagnostic Tool
  ════════════════════════════════════════════════════════════════
  
  ✓ Redis is accessible
  
  Listing all jobs with logs:
    job_123: 45 log entries
    job_456: 82 log entries
    job_789: 0 log entries (⚠ no logs)
  
  ════════════════════════════════════════════════════════════════

================================================================================
                           ✅ TEST VERIFICATION
================================================================================

FILE: test_fixes.py

DESCRIPTION:
  Comprehensive test suite verifying all critical fixes.
  Run after containers are fully started.

USAGE:
  python test_fixes.py

TESTS INCLUDED:
  1. Redis Connection
     → Verifies Redis is accessible on :6379
     → Tests basic ping
  
  2. State Manager
     → Creates job
     → Tests all state transitions
     → Verifies final state
  
  3. Logger
     → Tests logging at all levels
     → Verifies Redis storage
     → Retrieves and displays logs
  
  4. Security Module
     → Password hashing with bcrypt
     → Password verification
     → API key creation and validation
     → API key revocation
  
  5. HTTP Client
     → Makes async GET request
     → Tests rate limiting
     → Collects metrics
     → Proper cleanup

EXPECTED RESULTS:
  ✓ Redis Connection     PASS
  ✓ State Manager        PASS
  ✓ Logger               PASS
  ✓ Security             PASS
  ✓ HTTP Client          PASS
  
  Total: 5/5 passed
  ✓ All critical fixes verified successfully!

================================================================================
                         📚 CORE MODULES GUIDE
================================================================================

1. core/http_client.py
   ─────────────────────
   IMPORT: from core.http_client import HTTPClient, RateLimitConfig
   
   FEATURES:
   • Async HTTP requests with retries
   • Per-target rate limiting
   • Connection pooling
   • Automatic exponential backoff
   • Request metrics tracking
   
   QUICK USAGE:
   ────────────
   import asyncio
   from core.http_client import HTTPClient
   
   async def main():
       client = HTTPClient(timeout=12, max_retries=3)
       response = await client.get("http://example.com")
       print(f"Status: {response.status_code}")
       metrics = client.get_metrics()
       await client.close()
   
   asyncio.run(main())


2. core/state_manager.py
   ──────────────────────
   IMPORT: from core.state_manager import get_state_manager, JobStage
   
   FEATURES:
   • Enforced job state machine
   • Valid transition validation
   • Progress tracking
   • Metadata storage
   • Distribution metrics
   
   QUICK USAGE:
   ────────────
   from core.state_manager import get_state_manager, JobStage
   
   state_mgr = get_state_manager()
   
   # Create job
   state_mgr.create_job("job_1", {"target": "http://example.com"})
   
   # Transition through pipeline
   state_mgr.transition("job_1", JobStage.SCANNING, progress=25)
   state_mgr.transition("job_1", JobStage.EXPLOITING, progress=55)
   
   # Check state
   state = state_mgr.get_state("job_1")
   print(f"{state.current_stage.value}: {state.progress}%")


3. core/logger.py
   ───────────────
   IMPORT: from core.logger import get_logger
   
   FEATURES:
   • Structured JSON logging
   • Automatic Redis storage
   • Per-job log retrieval
   • Dual output (console + Redis)
   
   QUICK USAGE:
   ────────────
   from core.logger import get_logger
   
   logger = get_logger("my_component")
   
   # Log messages
   logger.info("Scan started", "job_1")
   logger.warning("Issue detected", "job_1", {"severity": "high"})
   logger.error("Scan failed", "job_1")
   
   # Retrieve logs
   logs = logger.get_job_logs("job_1", limit=100)
   for log in logs:
       print(f"[{log['timestamp']}] {log['message']}")


4. core/security.py
   ─────────────────
   IMPORT: from core.security import (
       PasswordManager, 
       get_api_key_manager,
       get_token_manager
   )
   
   FEATURES:
   • Bcrypt password hashing
   • Secure API key generation
   • Token management
   
   QUICK USAGE:
   ────────────
   # PASSWORD HASHING
   from core.security import PasswordManager
   
   pwd = "MySecurePassword123"
   hashed = PasswordManager.hash_password(pwd)
   
   if PasswordManager.verify_password(pwd, hashed):
       print("Correct password!")
   
   # API KEY MANAGEMENT
   from core.security import get_api_key_manager
   
   api_mgr = get_api_key_manager()
   key = api_mgr.create_key("user_123", "my_key", expires_in_days=30)
   
   if api_mgr.validate_key(key, "user_123"):
       print("Key is valid!")
   
   api_mgr.revoke_key("user_123", "my_key")

================================================================================
                          🚀 TYPICAL WORKFLOW
================================================================================

SCENARIO: Run a scan and monitor its progress

STEP 1: Start containers with progress monitoring
   Terminal 1:
   $ python monitor_build.py
   
   (Wait for all services to show ✓)

STEP 2: Verify all fixes work
   Terminal 2:
   $ python test_fixes.py
   
   (Should see "Total: 5/5 passed")

STEP 3: Submit a scan via API
   Terminal 3:
   $ curl -X POST http://localhost:8000/api/scan \\
     -H "Content-Type: application/json" \\
     -d '{"target": "http://example.com", "tier": "Professional"}'
   
   Response:
   {"job_id": "job_abc123", "status": "queued"}

STEP 4: Monitor job progression
   Terminal 2:
   $ python diagnose.py job_abc123
   
   Reload every 10 seconds to see progress
   
   Output:
   Checking job: job_abc123
   ✓ Found 5 log entries for job job_abc123:
     [10:30:45] [INIT] Job job_abc123 started on scan_queue
     [10:30:46] [SCAN] Starting scan for http://example.com
     [10:30:52] [SCAN] Complete - 3 vulnerabilities found
     [10:31:04] [EXPLOIT] Complete - 5 enriched findings
     [10:31:15] [AGGREGATION] Job complete

STEP 5: View final results
   Web browser:
   http://localhost:8501/
   
   (Streamlit dashboard shows job status and findings)

================================================================================
                          ⚠️  COMMON ISSUES
================================================================================

ISSUE: "Job exists but no logs"
───────────────────────────────
CAUSE: Old jobs created before fix, or worker crash
SOLUTION:
  1. Check worker status: docker-compose ps
  2. View worker logs: docker-compose logs scan_worker
  3. Verify Redis: python diagnose.py
  4. Check state manager: python -c "
     from core.state_manager import get_state_manager
     sm = get_state_manager()
     state = sm.get_state('job_id')
     print(state.current_stage.value)
     "

ISSUE: Containers won't start
─────────────────────────────
SOLUTION:
  1. Check build progress: python monitor_build.py
  2. View full logs: docker-compose logs
  3. Rebuild: docker-compose down -v && docker-compose build
  4. Start: docker-compose up -d

ISSUE: Tests fail with Redis connection error
──────────────────────────────────────────────
SOLUTION:
  1. Verify containers running: docker-compose ps
  2. Check Redis: docker-compose logs redis
  3. Test Redis: redis-cli ping
  4. Verify REDIS_URL env var set in .env

================================================================================
                        📖 DOCUMENTATION LINKS
================================================================================

COMPREHENSIVE GUIDE:
  Read: CRITICAL_FIXES_SUMMARY.md
  
  Topics:
  • All 10 critical fixes explained
  • Architecture improvements
  • Performance metrics
  • Security enhancements
  • Deployment checklist
  • Backward compatibility

CODE DOCUMENTATION:
  • core/http_client.py - Inline docstrings + type hints
  • core/state_manager.py - Inline docstrings + type hints
  • core/logger.py - Inline docstrings + type hints
  • core/security.py - Inline docstrings + type hints

WORKER UPDATES:
  • workers/scan_worker.py - Async HTTP scanning
  • workers/exploit_worker.py - State management
  • core/pipeline.py - Pipeline routing logic

================================================================================
                         💬 SUPPORT & DEBUGGING
================================================================================

GET HELP:
  1. Read error message carefully
  2. Check relevant log file (docker-compose logs SERVICE)
  3. Run diagnostic: python diagnose.py
  4. Run tests: python test_fixes.py
  5. Review CRITICAL_FIXES_SUMMARY.md

DEBUG COMMANDS:
  # Check Redis state
  redis-cli
  > KEYS *
  > GET job:{job_id}:findings_json
  
  # Check container logs
  docker-compose logs -f scan_worker
  docker-compose logs -f exploit_worker
  docker-compose logs -f api
  
  # Enter container
  docker-compose exec scan_worker bash
  
  # Check Python imports
  docker-compose exec api python -c "from core.http_client import HTTPClient; print('✓')"

================================================================================

For questions or issues, refer to:
• CRITICAL_FIXES_SUMMARY.md (comprehensive guide)
• Code docstrings (inline documentation)
• Docker logs (service diagnostics)
• Redis CLI (state inspection)

Happy scanning! 🎯

""")
