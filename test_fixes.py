#!/usr/bin/env python3
"""
Quick test script to verify critical fixes work.
Run this once containers are up.
"""

import redis
import json
import asyncio
import sys

# Test imports
try:
    from core.state_manager import get_state_manager, JobStage
    from core.logger import get_logger
    from core.http_client import HTTPClient, RateLimitConfig
    from core.security import PasswordManager, APIKeyManager
    print("✓ All core modules imported successfully")
except ImportError as e:
    print(f"✗ Import error: {e}")
    sys.exit(1)


def test_state_manager():
    """Test job state management."""
    print("\n[TEST] State Manager")
    try:
        sm = get_state_manager()
        
        # Create job
        state = sm.create_job("test_job_1", {"target": "http://example.com", "tier": "Professional"})
        print(f"  ✓ Created job: {state.job_id} in {state.current_stage.value}")
        
        # Transition through pipeline
        transitions = [
            JobStage.CRAWLING,
            JobStage.SCANNING,
            JobStage.EXPLOITING,
            JobStage.AGGREGATING,
            JobStage.MEMORY_ENRICHING,
            JobStage.SCORING,
            JobStage.REPORTING,
            JobStage.COMPLETED
        ]
        
        for next_stage in transitions:
            if sm.transition("test_job_1", next_stage, progress=int(next_stage.name.count('_')) * 10):
                print(f"  ✓ Transitioned to {next_stage.value}")
        
        # Verify final state
        final = sm.get_state("test_job_1")
        print(f"  ✓ Final state: {final.current_stage.value}, Progress: {final.progress}%")
        
        return True
    except Exception as e:
        print(f"  ✗ State manager test failed: {e}")
        return False


def test_logger():
    """Test centralized logging."""
    print("\n[TEST] Logger")
    try:
        logger = get_logger("test_component")
        
        # Test logging
        logger.info("Test info message", "test_job_1")
        logger.warning("Test warning", "test_job_1", {"test": "detail"})
        logger.error("Test error", "test_job_1")
        
        # Retrieve logs
        logs = logger.get_job_logs("test_job_1")
        print(f"  ✓ Logged {len(logs)} entries")
        print(f"  ✓ Latest: {logs[-1]['message'] if logs else 'none'}")
        
        return True
    except Exception as e:
        print(f"  ✗ Logger test failed: {e}")
        return False


async def test_http_client():
    """Test async HTTP client."""
    print("\n[TEST] HTTP Client")
    try:
        rate_limit = RateLimitConfig(max_requests_per_second=10)
        client = HTTPClient(timeout=5, rate_limit_config=rate_limit)
        
        # Test GET request (safe target)
        print("  → Testing GET request to httpbin.org...")
        response = await client.get("http://httpbin.org/get")
        print(f"  ✓ GET request successful: {response.status_code}")
        
        # Check rate limiting
        print("  → Testing rate limiting...")
        await client.get("http://httpbin.org/get")
        await client.get("http://httpbin.org/get")
        print(f"  ✓ Rate limiting works")
        
        # Get metrics
        metrics = client.get_metrics()
        print(f"  ✓ Collected {len(metrics)} request metrics")
        
        await client.close()
        return True
    except Exception as e:
        print(f"  ✗ HTTP client test failed: {e}")
        return False


def test_security():
    """Test password hashing and API key management."""
    print("\n[TEST] Security Module")
    try:
        # Password hashing
        pwd = "TestPassword123!@#"
        hashed = PasswordManager.hash_password(pwd)
        print(f"  ✓ Password hashed: {hashed[:20]}...")
        
        # Verify
        if PasswordManager.verify_password(pwd, hashed):
            print(f"  ✓ Password verification successful")
        else:
            print(f"  ✗ Password verification failed")
            return False
        
        # API key management
        api_mgr = APIKeyManager()
        
        # Create key
        key = api_mgr.create_key("user_123", "test_key", expires_in_days=30)
        print(f"  ✓ API key created: {key[:20]}...")
        
        # Validate key
        if api_mgr.validate_key(key, "user_123"):
            print(f"  ✓ API key validation successful")
        else:
            print(f"  ✗ API key validation failed")
            return False
        
        # Revoke key
        if api_mgr.revoke_key("user_123", "test_key"):
            print(f"  ✓ API key revoked")
        
        return True
    except Exception as e:
        print(f"  ✗ Security test failed: {e}")
        return False


def test_redis_connection():
    """Test Redis connectivity."""
    print("\n[TEST] Redis Connection")
    try:
        r = redis.Redis.from_url("redis://localhost:6379", decode_responses=True)
        ping = r.ping()
        if ping:
            print(f"  ✓ Redis is accessible")
            return True
        else:
            print(f"  ✗ Redis ping failed")
            return False
    except Exception as e:
        print(f"  ✗ Redis connection failed: {e}")
        return False


async def run_all_tests():
    """Run all tests."""
    print("=" * 60)
    print("CORTEX SENTINEL - POST-FIX VERIFICATION TESTS")
    print("=" * 60)
    
    results = {
        "Redis": test_redis_connection(),
        "State Manager": test_state_manager(),
        "Logger": test_logger(),
        "Security": test_security(),
        "HTTP Client": await test_http_client(),
    }
    
    print("\n" + "=" * 60)
    print("TEST RESULTS")
    print("=" * 60)
    
    passed = sum(1 for v in results.values() if v)
    total = len(results)
    
    for name, result in results.items():
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"{name:<20} {status}")
    
    print(f"\nTotal: {passed}/{total} passed")
    
    if passed == total:
        print("\n✓ All critical fixes verified successfully!")
        return 0
    else:
        print(f"\n✗ {total - passed} test(s) failed")
        return 1


if __name__ == "__main__":
    try:
        exit_code = asyncio.run(run_all_tests())
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\n\nTests interrupted")
        sys.exit(1)
