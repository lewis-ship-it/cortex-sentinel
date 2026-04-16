# utils/ci_gate.py
import sys
import json
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("CI_GATE")

def evaluate_build(report_path, threshold="High"):
    """
    Evaluates scan results. If findings meet or exceed the threshold, 
    it triggers a non-zero exit code to fail the CI/CD pipeline.
    """
    try:
        with open(report_path, 'r') as f:
            report_data = json.load(f)
        
        findings = report_data.get("findings", [])
        job_id = report_data.get("job_id", "Unknown")
        
        # Define severity weights
        severity_map = {"Critical": 3, "High": 2, "Medium": 1, "Low": 0}
        min_weight = severity_map.get(threshold, 2)
        
        failures = [f for f in findings if severity_map.get(f.get("severity"), 0) >= min_weight]
        
        if failures:
            logger.error(f"🛑 [SECURITY GATE] Job {job_id} FAILED.")
            logger.error(f"Detected {len(failures)} vulnerabilities at or above {threshold} level.")
            for f in failures:
                logger.error(f" - [{f['severity']}] {f['type']} in {f['url']}")
            
            # Exit code 1 tells GitHub/GitLab to stop the deployment
            sys.exit(1)
            
        logger.info(f"✅ [SECURITY GATE] Job {job_id} PASSED. No blocking vulnerabilities found.")
        sys.exit(0)

    except FileNotFoundError:
        logger.error("Report file not found. Ensure the scan worker completed successfully.")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Error evaluating security gate: {e}")
        sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python ci_gate.py <path_to_report.json>")
    else:
        evaluate_build(sys.argv[1])