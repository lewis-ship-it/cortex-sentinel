# scanner/dast/json_mutator.py
#
# ENHANCED JSON MUTATOR — Comprehensive JSON manipulation for security testing
# Supports multiple mutation strategies, path discovery, and security payload injection

import copy
import json
import logging
from typing import Any, Dict, List, Optional, Union, Generator, Tuple, Callable
from enum import Enum

logger = logging.getLogger(__name__)

class MutationStrategy(Enum):
    REPLACE = "replace"
    APPEND = "append"
    PREPEND = "prepend"
    TYPE_CONVERSION = "type_conversion"
    ARRAY_INJECTION = "array_injection"

class JSONMutator:
    def __init__(self, config: Optional[Dict] = None):
        self.config = {
            "max_depth": 20,
            "max_paths": 1000,
            "array_max_elements": 50,
            "string_mutation_prefix": "MUTATED_",
            "default_mutation_strategy": MutationStrategy.REPLACE,
            **(config or {})
        }
        
        # Common security testing payloads
        self.security_payloads = {
            "sql_injection": [
                "' OR '1'='1",
                "\" OR \"1\"=\"1",
                "'; DROP TABLE users; --",
                "1; SELECT * FROM users",
            ],
            "xss": [
                "<script>alert(1)</script>",
                "<img src=x onerror=alert(1)>",
                "javascript:alert(1)",
            ],
            "command_injection": [
                "; ls -la",
                "| cat /etc/passwd",
                "`whoami`",
                "$(id)",
            ],
            "path_traversal": [
                "../../../etc/passwd",
                "..\\..\\..\\windows\\win.ini",
                "....//....//etc/passwd",
            ],
            "xxe": [
                "<!ENTITY xxe SYSTEM \"file:///etc/passwd\">",
            ],
            "nosql": [
                {"$ne": None},
                {"$gt": ""},
                {"$where": "1 == 1"},
            ]
        }

    def mutate_json(
        self,
        data: Union[Dict, List],
        path: List[Union[str, int]],
        payload: Any,
        strategy: MutationStrategy = None
    ) -> Union[Dict, List]:
        """
        Mutate JSON data at the specified path using the given strategy.
        
        Args:
            data: The JSON data to mutate
            path: List of keys/indices to the target location
            payload: The value to insert or use for mutation
            strategy: Mutation strategy to use
            
        Returns:
            Mutated JSON data
        """
        if not path:
            return payload
            
        if strategy is None:
            strategy = self.config["default_mutation_strategy"]
            
        try:
            new_data = copy.deepcopy(data)
            current = new_data
            
            # Navigate to the parent of the target
            for key in path[:-1]:
                if isinstance(current, dict) and key in current:
                    current = current[key]
                elif isinstance(current, list) and isinstance(key, int) and 0 <= key < len(current):
                    current = current[key]
                else:
                    # Path doesn't exist, create it as a dict
                    if isinstance(current, dict):
                        current[key] = {}
                        current = current[key]
                    else:
                        raise ValueError(f"Cannot create path in non-dict container at {key}")
            
            # Apply mutation to the target
            target_key = path[-1]
            self._apply_mutation(current, target_key, payload, strategy)
            
            return new_data
            
        except (KeyError, IndexError, TypeError) as e:
            logger.error(f"Mutation failed for path {path}: {e}")
            raise ValueError(f"Invalid path or mutation strategy: {e}")

    def _apply_mutation(
        self,
        container: Union[Dict, List],
        key: Union[str, int],
        payload: Any,
        strategy: MutationStrategy
    ) -> None:
        """Apply mutation to a specific key in the container"""
        current_value = container[key] if (
            (isinstance(container, dict) and key in container) or
            (isinstance(container, list) and isinstance(key, int) and 0 <= key < len(container))
        ) else None
        
        if strategy == MutationStrategy.REPLACE:
            container[key] = payload
            
        elif strategy == MutationStrategy.APPEND:
            if isinstance(current_value, str) and isinstance(payload, str):
                container[key] = current_value + payload
            elif isinstance(current_value, list):
                container[key] = current_value + ([payload] if not isinstance(payload, list) else payload)
            else:
                container[key] = payload
                
        elif strategy == MutationStrategy.PREPEND:
            if isinstance(current_value, str) and isinstance(payload, str):
                container[key] = payload + current_value
            elif isinstance(current_value, list):
                container[key] = ([payload] if not isinstance(payload, list) else payload) + current_value
            else:
                container[key] = payload
                
        elif strategy == MutationStrategy.TYPE_CONVERSION:
            # Convert value to different type or inject type-confusion payloads
            if isinstance(current_value, (int, float)):
                container[key] = str(current_value) + str(payload)
            elif isinstance(current_value, str):
                try:
                    container[key] = int(payload)
                except (ValueError, TypeError):
                    container[key] = payload
            elif isinstance(current_value, bool):
                container[key] = not current_value
                
        elif strategy == MutationStrategy.ARRAY_INJECTION:
            if isinstance(current_value, list):
                # Inject payload into array
                if isinstance(payload, list):
                    container[key] = current_value + payload
                else:
                    container[key].append(payload)
            else:
                # Convert to array and inject
                container[key] = [current_value, payload]

    def get_json_paths(
        self,
        data: Union[Dict, List],
        current_path: Optional[List[Union[str, int]]] = None,
        depth: int = 0
    ) -> Generator[List[Union[str, int]], None, None]:
        """
        Generator that yields all possible paths in a JSON object.
        
        Args:
            data: JSON data to traverse
            current_path: Current path (used recursively)
            depth: Current depth (used for limiting)
            
        Yields:
            List of keys/indices representing the path
        """
        if current_path is None:
            current_path = []
            
        if depth > self.config["max_depth"]:
            return
            
        if isinstance(data, dict):
            for key, value in data.items():
                yield current_path + [key]
                yield from self.get_json_paths(value, current_path + [key], depth + 1)
                
        elif isinstance(data, list):
            for i, value in enumerate(data):
                if i < self.config["array_max_elements"]:  # Limit array traversal
                    yield current_path + [i]
                    yield from self.get_json_paths(value, current_path + [i], depth + 1)

    def get_paths_with_types(
        self,
        data: Union[Dict, List],
        filter_func: Optional[Callable[[Any], bool]] = None
    ) -> Generator[Tuple[List[Union[str, int]], Any], None, None]:
        """
        Get paths along with their values and types.
        
        Args:
            data: JSON data to traverse
            filter_func: Optional function to filter paths based on value
            
        Yields:
            Tuple of (path, value) for each leaf node
        """
        for path in self.get_json_paths(data):
            try:
                value = self.get_value_by_path(data, path)
                if filter_func is None or filter_func(value):
                    yield path, value
            except (KeyError, IndexError, TypeError):
                continue

    def get_value_by_path(
        self,
        data: Union[Dict, List],
        path: List[Union[str, int]]
    ) -> Any:
        """
        Get value from JSON data by path.
        
        Args:
            data: JSON data
            path: List of keys/indices
            
        Returns:
            Value at the specified path
        """
        current = data
        for key in path:
            if isinstance(current, dict) and key in current:
                current = current[key]
            elif isinstance(current, list) and isinstance(key, int) and 0 <= key < len(current):
                current = current[key]
            else:
                raise KeyError(f"Path not found: {key} in {path}")
        return current

    def generate_security_mutations(
        self,
        data: Union[Dict, List],
        payload_type: str = "sql_injection"
    ) -> Generator[Tuple[List[Union[str, int]], Any, MutationStrategy], None, None]:
        """
        Generate security-focused mutations for testing.
        
        Args:
            data: JSON data to mutate
            payload_type: Type of security payload to use
            
        Yields:
            Tuple of (path, payload, strategy) for each mutation
        """
        if payload_type not in self.security_payloads:
            raise ValueError(f"Unknown payload type: {payload_type}. Available: {list(self.security_payloads.keys())}")
            
        payloads = self.security_payloads[payload_type]
        
        for path, value in self.get_paths_with_types(data):
            for payload in payloads:
                # Choose strategy based on value type
                if isinstance(value, str):
                    yield path, payload, MutationStrategy.REPLACE
                    yield path, payload, MutationStrategy.APPEND
                    yield path, payload, MutationStrategy.PREPEND
                elif isinstance(value, (int, float)):
                    yield path, payload, MutationStrategy.TYPE_CONVERSION
                elif isinstance(value, list):
                    yield path, payload, MutationStrategy.ARRAY_INJECTION
                elif isinstance(value, bool):
                    yield path, payload, MutationStrategy.REPLACE
                elif value is None:
                    yield path, payload, MutationStrategy.REPLACE

    def mutate_for_fuzzing(
        self,
        data: Union[Dict, List],
        num_mutations: int = 10
    ) -> Generator[Union[Dict, List], None, None]:
        """
        Generate multiple mutated versions for fuzzing.
        
        Args:
            data: JSON data to mutate
            num_mutations: Number of mutations to generate
            
        Yields:
            Mutated JSON data
        """
        paths = list(self.get_json_paths(data))
        if not paths:
            yield data
            return
            
        # Generate various types of mutations
        mutation_types = list(MutationStrategy)
        
        for i in range(min(num_mutations, len(paths) * len(mutation_types))):
            path = paths[i % len(paths)]
            strategy = mutation_types[(i // len(paths)) % len(mutation_types)]
            
            # Generate appropriate payload based on current value
            try:
                current_value = self.get_value_by_path(data, path)
                payload = self._generate_payload_for_value(current_value, strategy)
                
                mutated = self.mutate_json(data, path, payload, strategy)
                yield mutated
                
            except (KeyError, IndexError, ValueError):
                continue

    def _generate_payload_for_value(
        self,
        value: Any,
        strategy: MutationStrategy
    ) -> Any:
        """Generate appropriate payload based on value type and strategy"""
        if strategy == MutationStrategy.TYPE_CONVERSION:
            if isinstance(value, (int, float)):
                return "string_payload"
            elif isinstance(value, str):
                return 999999
            elif isinstance(value, bool):
                return "true" if not value else "false"
                
        elif strategy in (MutationStrategy.APPEND, MutationStrategy.PREPEND):
            if isinstance(value, str):
                return "_injected"
            elif isinstance(value, list):
                return ["injected_item"]
                
        # Default payloads
        if isinstance(value, str):
            return "injected_value"
        elif isinstance(value, (int, float)):
            return 1337
        elif isinstance(value, bool):
            return not value
        elif isinstance(value, list):
            return ["injected_element"]
        elif value is None:
            return "injected"
        else:
            return "malformed_payload"

    def to_json_path_string(self, path: List[Union[str, int]]) -> str:
        """Convert path list to JSONPath-like string"""
        path_str = "$"
        for key in path:
            if isinstance(key, str):
                path_str += f".{key}"
            elif isinstance(key, int):
                path_str += f"[{key}]"
        return path_str

    def from_json_path_string(self, path_str: str) -> List[Union[str, int]]:
        """Convert JSONPath-like string to path list"""
        if not path_str.startswith("$"):
            raise ValueError("JSONPath must start with '$'")
            
        path = []
        components = path_str[1:].split('.')
        
        for comp in components:
            if comp == "":
                continue
            # Handle array indices
            if '[' in comp and comp.endswith(']'):
                base, indices = comp.split('[', 1)
                if base:
                    path.append(base)
                # Extract all indices
                for idx_str in indices.rstrip(']').split(']['):
                    try:
                        path.append(int(idx_str))
                    except ValueError:
                        path.append(idx_str)
            else:
                path.append(comp)
                
        return path

# Legacy functions for backward compatibility
def mutate_json(data, path, payload):
    """Legacy function for backward compatibility"""
    mutator = JSONMutator()
    return mutator.mutate_json(data, path, payload)

def get_json_paths(data, current_path=None):
    """Legacy function for backward compatibility"""
    mutator = JSONMutator()
    if current_path is None:
        return list(mutator.get_json_paths(data))
    else:
        return list(mutator.get_json_paths(data, current_path))
