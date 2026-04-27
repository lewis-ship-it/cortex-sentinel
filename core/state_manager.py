
"""
core/state_manager.py

Enforces valid job state transitions and completion integrity.
Prevents jobs from skipping stages or completing prematurely.
"""

import json
import redis
import logging
from enum import Enum
from typing import Optional, Dict, List
from datetime import datetime
import os

logger = logging.getLogger(__name__)

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")


class JobStage(Enum):
    """Valid job stages in the pipeline."""
    CREATED = "created"
    CRAWLING = "crawling"
    SCANNING = "scanning"
    EXPLOITING = "exploiting"
    AGGREGATING = "aggregating"
    MEMORY_ENRICHING = "memory_enriching"
    SCORING = "scoring"
    REPORTING = "reporting"
    COMPLETED = "completed"
    FAILED = "failed"


class StateTransition:
    """Define valid transitions between states."""
    
    # Valid transitions: from_state -> [to_states]
    VALID_TRANSITIONS = {
        JobStage.CREATED: [JobStage.CRAWLING],
        JobStage.CRAWLING: [JobStage.SCANNING, JobStage.FAILED],
        JobStage.SCANNING: [JobStage.EXPLOITING, JobStage.AGGREGATING, JobStage.FAILED],
        JobStage.EXPLOITING: [JobStage.AGGREGATING, JobStage.FAILED],
        JobStage.AGGREGATING: [JobStage.MEMORY_ENRICHING, JobStage.SCORING, JobStage.REPORTING, JobStage.FAILED],
        JobStage.MEMORY_ENRICHING: [JobStage.SCORING, JobStage.FAILED],
        JobStage.SCORING: [JobStage.REPORTING, JobStage.COMPLETED, JobStage.FAILED],
        JobStage.REPORTING: [JobStage.COMPLETED, JobStage.FAILED],
        JobStage.COMPLETED: [],  # No transitions from completed
        JobStage.FAILED: [],  # No transitions from failed
    }
    
    @staticmethod
    def is_valid(from_stage: JobStage, to_stage: JobStage) -> bool:
        """Check if transition is valid."""
        return to_stage in StateTransition.VALID_TRANSITIONS.get(from_stage, [])


class JobState:
    """Represents a job's current state with metadata."""
    
    def __init__(
        self,
        job_id: str,
        current_stage: JobStage,
        progress: int = 0,
        metadata: Optional[Dict] = None,
        created_at: Optional[str] = None
    ):
        self.job_id = job_id
        self.current_stage = current_stage
        self.progress = progress
        self.metadata = metadata or {}
        self.created_at = created_at or datetime.utcnow().isoformat()
    
    def to_dict(self) -> Dict:
        """Convert to dict for Redis storage."""
        return {
            "job_id": self.job_id,
            "current_stage": self.current_stage.value,
            "progress": self.progress,
            "metadata": json.dumps(self.metadata),
            "created_at": self.created_at,
            "updated_at": datetime.utcnow().isoformat()
        }
    
    @staticmethod
    def from_dict(data: Dict) -> "JobState":
        """Reconstruct from dict."""
        return JobState(
            job_id=data.get("job_id"),
            current_stage=JobStage(data.get("current_stage", "created")),
            progress=int(data.get("progress", 0)),
            metadata=json.loads(data.get("metadata", "{}")),
            created_at=data.get("created_at")
        )


class StateManager:
    """
    Manages job state transitions with validation.
    Ensures jobs follow the correct pipeline flow.
    """
    
    def __init__(self, redis_url: str = REDIS_URL):
        self.r = redis.Redis.from_url(redis_url, decode_responses=True)
    
    def create_job(self, job_id: str, metadata: Optional[Dict] = None) -> JobState:
        """
        Create a new job in CREATED state.
        
        Args:
            job_id: Unique job identifier
            metadata: Optional metadata dict (target, tier, etc.)
            
        Returns:
            JobState object
        """
        state = JobState(
            job_id=job_id,
            current_stage=JobStage.CREATED,
            progress=0,
            metadata=metadata or {}
        )
        
        self._save_state(state)
        logger.info(f"Created job {job_id} in CREATED stage")
        
        return state
    
    def get_state(self, job_id: str) -> Optional[JobState]:
        """Get current state of a job."""
        data = self.r.hgetall(f"job_state:{job_id}")
        
        if not data:
            logger.warning(f"No state found for job {job_id}")
            return None
        
        return JobState.from_dict(data)
    
    def transition(
        self,
        job_id: str,
        to_stage: JobStage,
        progress: int = None,
        metadata_update: Optional[Dict] = None
    ) -> bool:
        """
        Transition job to a new stage.
        
        Args:
            job_id: Job ID
            to_stage: Target stage
            progress: Optional progress percentage (0-100)
            metadata_update: Optional dict to merge with current metadata
            
        Returns:
            True if transition succeeded, False otherwise
        """
        current_state = self.get_state(job_id)
        
        if not current_state:
            logger.error(f"Cannot transition: job {job_id} has no state")
            return False
        
        # Validate transition
        if not StateTransition.is_valid(current_state.current_stage, to_stage):
            logger.error(
                f"Invalid transition for job {job_id}: "
                f"{current_state.current_stage.value} → {to_stage.value}"
            )
            return False
        
        # Update state
        current_state.current_stage = to_stage
        
        if progress is not None:
            current_state.progress = max(0, min(100, progress))
        
        if metadata_update:
            current_state.metadata.update(metadata_update)
        
        self._save_state(current_state)
        
        logger.info(
            f"Transitioned job {job_id}: {current_state.current_stage.value} "
            f"(progress: {current_state.progress}%)"
        )
        
        return True
    
    def fail_job(self, job_id: str, reason: str) -> bool:
        """
        Mark a job as failed.
        
        Args:
            job_id: Job ID
            reason: Reason for failure
            
        Returns:
            True if successful
        """
        current_state = self.get_state(job_id)
        
        if not current_state:
            logger.error(f"Cannot fail: job {job_id} has no state")
            return False
        
        # All states can transition to FAILED
        current_state.current_stage = JobStage.FAILED
        current_state.progress = 100
        current_state.metadata["failure_reason"] = reason
        current_state.metadata["failed_at"] = datetime.utcnow().isoformat()
        
        self._save_state(current_state)
        
        logger.error(f"Job {job_id} marked as FAILED: {reason}")
        
        return True
    
    def complete_job(self, job_id: str) -> bool:
        """
        Mark a job as completed.
        
        Args:
            job_id: Job ID
            
        Returns:
            True if successful
        """
        current_state = self.get_state(job_id)
        
        if not current_state:
            logger.error(f"Cannot complete: job {job_id} has no state")
            return False
        
        current_state.current_stage = JobStage.COMPLETED
        current_state.progress = 100
        current_state.metadata["completed_at"] = datetime.utcnow().isoformat()
        
        self._save_state(current_state)
        
        logger.info(f"Job {job_id} marked as COMPLETED")
        
        return True
    
    def _save_state(self, state: JobState):
        """Save state to Redis."""
        data = state.to_dict()
        key = f"job_state:{state.job_id}"
        
        # Clear old hash
        self.r.delete(key)
        
        # Save new state
        self.r.hset(key, mapping=data)
        
        # Set TTL (30 days)
        self.r.expire(key, 30 * 24 * 60 * 60)
    
    def get_all_jobs(self, stage: Optional[JobStage] = None) -> List[JobState]:
        """
        Get all jobs, optionally filtered by stage.
        
        Args:
            stage: Optional stage to filter by
            
        Returns:
            List of JobState objects
        """
        keys = self.r.keys("job_state:*")
        jobs = []
        
        for key in keys:
            data = self.r.hgetall(key)
            state = JobState.from_dict(data)
            
            if stage is None or state.current_stage == stage:
                jobs.append(state)
        
        return jobs
    
    def get_stage_distribution(self) -> Dict[str, int]:
        """Get count of jobs in each stage."""
        distribution = {stage.value: 0 for stage in JobStage}
        
        jobs = self.get_all_jobs()
        for job in jobs:
            distribution[job.current_stage.value] += 1
        
        return distribution


# Singleton instance
_state_manager: Optional[StateManager] = None

def get_state_manager(redis_url: str = REDIS_URL) -> StateManager:
    """Get or create state manager."""
    global _state_manager
    if _state_manager is None:
        _state_manager = StateManager(redis_url)
    return _state_manager

