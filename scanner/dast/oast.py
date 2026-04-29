# scanner/dast/oast.py
#
# ENHANCED OAST (Out-of-Band Security Testing) MANAGER
# Supports multiple providers: Interactsh, custom servers, and multiple protocols

import asyncio
import httpx
import uuid
import logging
import time
import base64
import hashlib
from typing import Dict, List, Optional, Set, Any, Tuple
from enum import Enum
from urllib.parse import urlparse, urljoin

logger = logging.getLogger(__name__)

class OASTProtocol(Enum):
    DNS = "dns"
    HTTP = "http"
    HTTPS = "https"
    SMTP = "smtp"
    ALL = "all"

class OASTProvider(Enum):
    INTERACTSH = "interactsh"
    BURP = "burp"
    CUSTOM = "custom"

class OASTManager:
    """Comprehensive Out-of-Band Security Testing manager"""
    
    def __init__(self, config: Optional[Dict] = None):
        self.config = {
            "provider": OASTProvider.INTERACTSH,
            "server": "interact.sh",
            "protocols": [OASTProtocol.DNS, OASTProtocol.HTTP],
            "poll_interval": 5,
            "timeout": 30,
            "max_poll_attempts": 12,
            "correlation_length": 20,
            "auto_cleanup": True,
            "verify_ssl": True,
            **(config or {})
        }
        
        self.correlation_id = self._generate_correlation_id()
        self.domain = f"{self.correlation_id}.{self.config['server']}"
        self.registered = False
        self.session_token = None
        self.secret_key = None
        self.interactions: List[Dict] = []
        self._client: Optional[httpx.AsyncClient] = None
        self._poll_task: Optional[asyncio.Task] = None

    def _generate_correlation_id(self) -> str:
        """Generate a unique correlation ID"""
        return str(uuid.uuid4()).replace("-", "")[:self.config["correlation_length"]]

    async def __aenter__(self):
        await self.register()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.config["auto_cleanup"]:
            await self.deregister()
        if self._client:
            await self._client.aclose()

    async def register(self) -> bool:
        """Register with OAST server"""
        try:
            self._client = httpx.AsyncClient(
                timeout=self.config["timeout"],
                verify=self.config["verify_ssl"]
            )
            
            if self.config["provider"] == OASTProvider.INTERACTSH:
                return await self._register_interactsh()
            elif self.config["provider"] == OASTProvider.BURP:
                return await self._register_burp()
            elif self.config["provider"] == OASTProvider.CUSTOM:
                return await self._register_custom()
            else:
                raise ValueError(f"Unsupported provider: {self.config['provider']}")
                
        except Exception as e:
            logger.error(f"OAST registration failed: {e}")
            return False

    async def _register_interactsh(self) -> bool:
        """Register with Interactsh server"""
        self.secret_key = str(uuid.uuid4())
        payload = {
            "public-key": "",
            "secret-key": self.secret_key,
            "correlation-id": self.correlation_id,
        }
        
        try:
            response = await self._client.post(
                f"https://{self.config['server']}/register",
                json=payload,
            )
            
            if response.status_code == 200:
                data = response.json()
                self.session_token = data.get("token")
                self.registered = True
                logger.info(f"Registered OAST domain: {self.domain}")
                return True
            else:
                logger.warning(f"Interactsh registration failed: {response.status_code}")
                return False
                
        except Exception as e:
            logger.error(f"Interactsh registration error: {e}")
            return False

    async def _register_burp(self) -> bool:
        """Register with Burp Collaborator (simplified)"""
        # Burp Collaborator requires manual setup, so we just generate a domain
        self.registered = True
        logger.info(f"Using Burp Collaborator domain: {self.domain}")
        return True

    async def _register_custom(self) -> bool:
        """Register with custom OAST server"""
        # Custom server implementation would go here
        self.registered = True
        logger.info(f"Using custom OAST domain: {self.domain}")
        return True

    async def deregister(self) -> bool:
        """Deregister from OAST server"""
        if not self.registered:
            return True
            
        try:
            if self.config["provider"] == OASTProvider.INTERACTSH:
                response = await self._client.post(
                    f"https://{self.config['server']}/deregister",
                    json={
                        "token": self.session_token,
                        "secret-key": self.secret_key,
                    },
                )
                if response.status_code == 200:
                    logger.info("Successfully deregistered from OAST server")
            elif self.config["provider"] in (OASTProvider.BURP, OASTProvider.CUSTOM):
                # No deregistration needed for Burp or custom servers
                pass
                
        except Exception as e:
            logger.warning(f"OAST deregistration failed: {e}")
        finally:
            self.registered = False
            if self._client:
                await self._client.aclose()
                self._client = None
            return True

    def generate_payload(self, protocol: OASTProtocol = OASTProtocol.HTTP, 
                       additional_data: str = "") -> str:
        """Generate OAST payload for specific protocol"""
        if not self.registered:
            raise RuntimeError("OAST manager not registered")
            
        base_payload = self.domain
        
        if additional_data:
            # Encode additional data for the payload
            encoded_data = base64.urlsafe_b64encode(
                additional_data.encode()
            ).decode().rstrip("=")
            base_payload = f"{encoded_data}.{base_payload}"
            
        if protocol == OASTProtocol.DNS:
            return base_payload
        elif protocol in (OASTProtocol.HTTP, OASTProtocol.HTTPS):
            scheme = "https" if protocol == OASTProtocol.HTTPS else "http"
            return f"{scheme}://{base_payload}/ping"
        elif protocol == OASTProtocol.SMTP:
            return f"test@{base_payload}"
        else:
            return base_payload

    async def poll(self) -> List[Dict]:
        """Poll for interactions"""
        if not self.registered:
            return []
            
        try:
            if self.config["provider"] == OASTProvider.INTERACTSH:
                return await self._poll_interactsh()
            elif self.config["provider"] == OASTProvider.BURP:
                return await self._poll_burp()
            elif self.config["provider"] == OASTProvider.CUSTOM:
                return await self._poll_custom()
            else:
                return []
                
        except Exception as e:
            logger.error(f"OAST polling failed: {e}")
            return []

    async def _poll_interactsh(self) -> List[Dict]:
        """Poll Interactsh server for interactions"""
        try:
            response = await self._client.get(
                f"https://{self.config['server']}/poll",
                params={
                    "id": self.correlation_id,
                    "token": self.session_token,
                },
            )
            
            if response.status_code == 200:
                data = response.json()
                interactions = data.get("data", [])
                processed = self._process_interactions(interactions)
                self.interactions.extend(processed)
                return processed
            else:
                logger.debug(f"Interactsh poll returned {response.status_code}")
                return []
                
        except Exception as e:
            logger.debug(f"Interactsh poll error: {e}")
            return []

    async def _poll_burp(self) -> List[Dict]:
        """Poll Burp Collaborator (simulated)"""
        # Burp Collaborator polling would require specific implementation
        # For now, return empty list as we can't actually poll Burp
        return []

    async def _poll_custom(self) -> List[Dict]:
        """Poll custom OAST server"""
        # Custom server polling implementation would go here
        return []

    def _process_interactions(self, raw_interactions: List[Dict]) -> List[Dict]:
        """Process raw interactions into standardized format"""
        processed = []
        
        for interaction in raw_interactions:
            try:
                processed_interaction = {
                    "protocol": interaction.get("protocol", "unknown"),
                    "remote_address": interaction.get("remote-address", "unknown"),
                    "timestamp": interaction.get("timestamp", time.time()),
                    "raw_request": interaction.get("raw-request", ""),
                    "full_id": interaction.get("full-id", ""),
                    "correlation_id": self.correlation_id,
                }
                
                # Extract additional info based on protocol
                if processed_interaction["protocol"] == "dns":
                    processed_interaction["query_type"] = interaction.get("q-type", "")
                    processed_interaction["query_name"] = interaction.get("q-name", "")
                    
                elif processed_interaction["protocol"] in ("http", "https"):
                    processed_interaction["method"] = interaction.get("method", "")
                    processed_interaction["host"] = interaction.get("host", "")
                    processed_interaction["path"] = interaction.get("path", "")
                    
                processed.append(processed_interaction)
                
            except Exception as e:
                logger.debug(f"Failed to process interaction: {e}")
                continue
                
        return processed

    async def start_polling(self) -> None:
        """Start automatic polling in background"""
        if self._poll_task and not self._poll_task.done():
            return
            
        self._poll_task = asyncio.create_task(self._poll_loop())

    async def stop_polling(self) -> None:
        """Stop automatic polling"""
        if self._poll_task:
            self._poll_task.cancel()
            try:
                await self._poll_task
            except asyncio.CancelledError:
                pass
            self._poll_task = None

    async def _poll_loop(self) -> None:
        """Background polling loop"""
        attempt = 0
        while attempt < self.config["max_poll_attempts"]:
            try:
                interactions = await self.poll()
                if interactions:
                    logger.info(f"Detected {len(interactions)} OAST interactions")
                    attempt = 0  # Reset attempt counter on success
                else:
                    attempt += 1
                    
                await asyncio.sleep(self.config["poll_interval"])
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Polling loop error: {e}")
                attempt += 1
                await asyncio.sleep(self.config["poll_interval"])

    def has_interactions(self) -> bool:
        """Check if any interactions have been detected"""
        return len(self.interactions) > 0

    def get_interactions(self) -> List[Dict]:
        """Get all detected interactions"""
        return self.interactions.copy()

    def clear_interactions(self) -> None:
        """Clear stored interactions"""
        self.interactions.clear()

    def wait_for_interaction(self, timeout: Optional[float] = None) -> bool:
        """
        Wait for an interaction (synchronous, for use in async contexts)
        Not recommended for production - use async polling instead
        """
        import time
        start_time = time.time()
        timeout = timeout or self.config["timeout"]
        
        while time.time() - start_time < timeout:
            if self.has_interactions():
                return True
            time.sleep(1)
            
        return False

# Simplified version for backward compatibility
class SimpleOASTManager:
    """Simplified OAST manager for backward compatibility"""
    
    def __init__(self):
        self.manager = OASTManager({
            "poll_interval": 5,
            "max_poll_attempts": 12,
        })
        self.domain = self.manager.domain

    async def register(self) -> bool:
        return await self.manager.register()

    async def poll_interactions(self) -> List[Dict]:
        interactions = await self.manager.poll()
        return [{"remote_ip": "OAST-HIT", "protocol": "DNS/HTTP"}] if interactions else []

# Global instance for simple usage
_global_oast_manager: Optional[OASTManager] = None

async def get_global_oast_manager() -> OASTManager:
    """Get or create global OAST manager instance"""
    global _global_oast_manager
    if _global_oast_manager is None:
        _global_oast_manager = OASTManager()
        await _global_oast_manager.register()
    return _global_oast_manager

async def cleanup_global_oast_manager() -> None:
    """Cleanup global OAST manager"""
    global _global_oast_manager
    if _global_oast_manager:
        await _global_oast_manager.deregister()
        _global_oast_manager = None
