
import time
import logging

logger = logging.getLogger(__name__)

class UsageTracker:
    def __init__(self, max_budget_usd=2.00):
        self.start_time = time.time()
        self.max_budget = max_budget_usd
        self.is_active = True  # The Kill Switch state
        
        self.stats = {
            "total_requests": 0,
            "ai_validations": 0,
            "waf_bypasses": 0,  # Added this key
            "oast_polls": 0,
            "estimated_cost_usd": 0.0
        }
            
        # Pricing constants (Adjust based on Gemini 1.5 Flash rates)
        self.COST_PER_1K_TOKENS = 0.000125  
        self.COST_PER_REQ = 0.00001 

    def _check_budget(self):
        """Internal check to flip the kill switch."""
        if self.stats["estimated_cost_usd"] >= self.max_budget:
            self.is_active = False
            logger.critical(f"!!! KILL SWITCH TRIGGERED: Budget of ${self.max_budget} reached !!!")    

    def log_request(self):
        if not self.is_active: return
        self.stats["total_requests"] += 1
        self.stats["estimated_cost_usd"] += self.COST_PER_REQ
        self._check_budget() # Check after every update
    
    def log_waf_bypass(self):
        """Logs when AI logic or adaptive jitter is used to clear a 403/429."""
        if not self.is_active: return
        self.stats["waf_bypasses"] += 1
        # Bypasses usually involve extra logic/time, you might want to add a small cost here too

    def log_ai_usage(self, input_chars, output_chars):
        if not self.is_active: return
        self.stats["ai_validations"] += 1
        # Rough token estimation (4 chars per token)
        tokens = (input_chars + output_chars) / 4
        cost = (tokens / 1000) * self.COST_PER_1K_TOKENS
        self.stats["estimated_cost_usd"] += cost
        self._check_budget() # Check after every update

    def get_final_metrics(self):
        self.stats["duration_seconds"] = round(time.time() - self.start_time, 2)
        # Added a safety check in case is_active was never flipped
        self.stats["budget_tripped"] = not self.is_active
        return self.stats

