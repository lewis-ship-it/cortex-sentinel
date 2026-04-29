# scanner/dast/payload_mutator.py
#
# ENHANCED PAYLOAD MUTATOR — Comprehensive WAF-bypass payload generation
# Supports: Multiple encoding schemes, language-specific obfuscation, context-aware mutations

import urllib.parse
import base64
import html
import random
import re
from typing import List, Optional, Dict, Any, Generator
from enum import Enum

class MutationTechnique(Enum):
    URL_ENCODING = "url_encoding"
    DOUBLE_URL_ENCODING = "double_url_encoding"
    HTML_ENTITY = "html_entity"
    BASE64 = "base64"
    SQL_COMMENT = "sql_comment"
    CASE_MANGLING = "case_mangling"
    WHITESPACE = "whitespace"
    NULL_BYTE = "null_byte"
    UNICODE = "unicode"
    HEX = "hex"
    UTF16 = "utf16"
    UTF32 = "utf32"
    STRING_SPLIT = "string_split"
    VARIABLE_OBFUSCATION = "variable_obfuscation"
    COMMENT_VARIATION = "comment_variation"

class PayloadContext(Enum):
    SQL = "sql"
    XSS = "xss"
    COMMAND = "command"
    PATH = "path"
    XXE = "xxe"
    GENERAL = "general"

class PayloadMutator:
    def __init__(self, config: Optional[Dict] = None):
        self.config = {
            "max_mutations": 50,
            "max_mutations_per_type": 5,
            "enable_dangerous_mutations": False,
            "default_context": PayloadContext.GENERAL,
            "technique_weights": {
                MutationTechnique.URL_ENCODING: 1.0,
                MutationTechnique.DOUBLE_URL_ENCODING: 0.8,
                MutationTechnique.HTML_ENTITY: 0.7,
                MutationTechnique.BASE64: 0.6,
                MutationTechnique.SQL_COMMENT: 0.9,
                MutationTechnique.CASE_MANGLING: 0.8,
                MutationTechnique.WHITESPACE: 0.7,
                MutationTechnique.UNICODE: 0.6,
                MutationTechnique.HEX: 0.5,
                MutationTechnique.UTF16: 0.4,
                MutationTechnique.UTF32: 0.3,
                MutationTechnique.STRING_SPLIT: 0.5,
                MutationTechnique.VARIABLE_OBFUSCATION: 0.4,
                MutationTechnique.COMMENT_VARIATION: 0.6,
            },
            "context_specific_techniques": {
                PayloadContext.SQL: [
                    MutationTechnique.SQL_COMMENT,
                    MutationTechnique.HEX,
                    MutationTechnique.CASE_MANGLING,
                    MutationTechnique.WHITESPACE,
                ],
                PayloadContext.XSS: [
                    MutationTechnique.HTML_ENTITY,
                    MutationTechnique.UNICODE,
                    MutationTechnique.URL_ENCODING,
                    MutationTechnique.BASE64,
                ],
                PayloadContext.COMMAND: [
                    MutationTechnique.CASE_MANGLING,
                    MutationTechnique.WHITESPACE,
                    MutationTechnique.NULL_BYTE,
                ],
                PayloadContext.PATH: [
                    MutationTechnique.URL_ENCODING,
                    MutationTechnique.DOUBLE_URL_ENCODING,
                    MutationTechnique.UNICODE,
                ],
                PayloadContext.XXE: [
                    MutationTechnique.URL_ENCODING,
                    MutationTechnique.HTML_ENTITY,
                ],
                PayloadContext.GENERAL: list(MutationTechnique),
            }
        }
        
        if config:
            self.config.update(config)

    def mutate(self, payload: str, context: Optional[PayloadContext] = None) -> List[str]:
        """
        Generate all WAF-bypass variants of a payload.
        
        Args:
            payload: The original payload to mutate
            context: Optional context for context-aware mutations
            
        Returns:
            List of mutated payload variants
        """
        if context is None:
            context = self.config["default_context"]
            
        variants = set([payload])
        
        # Get techniques for this context
        techniques = self.config["context_specific_techniques"][context]
        
        for technique in techniques:
            if len(variants) >= self.config["max_mutations"]:
                break
                
            technique_variants = self._apply_technique(payload, technique, context)
            for variant in technique_variants:
                if len(variants) < self.config["max_mutations"]:
                    variants.add(variant)
                else:
                    break
                    
        return list(variants)

    def mutate_generator(self, payload: str, context: Optional[PayloadContext] = None) -> Generator[str, None, None]:
        """
        Generate mutations as a generator for memory efficiency.
        
        Args:
            payload: The original payload to mutate
            context: Optional context for context-aware mutations
            
        Yields:
            Mutated payload variants
        """
        if context is None:
            context = self.config["default_context"]
            
        yield payload
        
        techniques = self.config["context_specific_techniques"][context]
        count = 1
        
        for technique in techniques:
            if count >= self.config["max_mutations"]:
                break
                
            technique_variants = self._apply_technique(payload, technique, context)
            for variant in technique_variants:
                if count < self.config["max_mutations"]:
                    yield variant
                    count += 1
                else:
                    break

    def _apply_technique(self, payload: str, technique: MutationTechnique, 
                        context: PayloadContext) -> List[str]:
        """Apply a specific mutation technique to a payload."""
        variants = set()
        
        try:
            if technique == MutationTechnique.URL_ENCODING:
                variants.add(urllib.parse.quote(payload))
                
            elif technique == MutationTechnique.DOUBLE_URL_ENCODING:
                double_encoded = urllib.parse.quote(urllib.parse.quote(payload))
                variants.add(double_encoded)
                
            elif technique == MutationTechnique.HTML_ENTITY:
                html_encoded = html.escape(payload)
                if html_encoded != payload:
                    variants.add(html_encoded)
                    
            elif technique == MutationTechnique.BASE64:
                try:
                    b64_encoded = base64.b64encode(payload.encode()).decode()
                    variants.add(b64_encoded)
                except UnicodeEncodeError:
                    pass
                    
            elif technique == MutationTechnique.SQL_COMMENT:
                sql_variants = self._sql_comment_mutations(payload)
                variants.update(sql_variants)
                
            elif technique == MutationTechnique.CASE_MANGLING:
                case_variants = self._case_mangling_mutations(payload)
                variants.update(case_variants)
                
            elif technique == MutationTechnique.WHITESPACE:
                whitespace_variants = self._whitespace_mutations(payload)
                variants.update(whitespace_variants)
                
            elif technique == MutationTechnique.NULL_BYTE:
                if self.config["enable_dangerous_mutations"]:
                    null_variants = self._null_byte_mutations(payload)
                    variants.update(null_variants)
                    
            elif technique == MutationTechnique.UNICODE:
                unicode_variants = self._unicode_mutations(payload)
                variants.update(unicode_variants)
                
            elif technique == MutationTechnique.HEX:
                hex_variants = self._hex_mutations(payload)
                variants.update(hex_variants)
                
            elif technique == MutationTechnique.UTF16:
                utf16_variants = self._utf16_mutations(payload)
                variants.update(utf16_variants)
                
            elif technique == MutationTechnique.UTF32:
                utf32_variants = self._utf32_mutations(payload)
                variants.update(utf32_variants)
                
            elif technique == MutationTechnique.STRING_SPLIT:
                split_variants = self._string_split_mutations(payload, context)
                variants.update(split_variants)
                
            elif technique == MutationTechnique.VARIABLE_OBFUSCATION:
                var_variants = self._variable_obfuscation_mutations(payload, context)
                variants.update(var_variants)
                
            elif technique == MutationTechnique.COMMENT_VARIATION:
                comment_variants = self._comment_variation_mutations(payload, context)
                variants.update(comment_variants)
                
        except Exception as e:
            # Silently skip mutations that fail
            pass
            
        return list(variants)[:self.config["max_mutations_per_type"]]

    def _sql_comment_mutations(self, payload: str) -> List[str]:
        """Generate SQL comment-based mutations."""
        variants = set()
        
        # Basic comment patterns
        comment_patterns = [
            ("SELECT", "SE/**/LECT"),
            ("UNION", "UN/**/ION"),
            ("OR", "/**/OR/**/"),
            ("AND", "/**/AND/**/"),
            ("FROM", "FR/**/OM"),
            ("WHERE", "WHE/**/RE"),
            ("INSERT", "INS/**/ERT"),
            ("UPDATE", "UP/**/DATE"),
            ("DELETE", "DEL/**/ETE"),
        ]
        
        for old, new in comment_patterns:
            if old in payload.upper():
                variant = payload.upper().replace(old, new)
                variants.add(variant)
                
        # Multiple comment styles
        comment_styles = ["/**/", "--", "#", "/*!", "*/"]
        for style in comment_styles:
            if " " in payload:
                variant = payload.replace(" ", style)
                variants.add(variant)
                
        return list(variants)

    def _case_mangling_mutations(self, payload: str) -> List[str]:
        """Generate case mangling mutations."""
        variants = set()
        
        # Random case
        random_case = ''.join(
            c.upper() if random.random() > 0.5 else c.lower() 
            for c in payload
        )
        variants.add(random_case)
        
        # Alternating case
        alternating = ''.join(
            c.upper() if i % 2 == 0 else c.lower() 
            for i, c in enumerate(payload)
        )
        variants.add(alternating)
        
        # Upper case
        variants.add(payload.upper())
        
        # Lower case
        variants.add(payload.lower())
        
        # Capitalize first letter
        if payload:
            capitalized = payload[0].upper() + payload[1:].lower()
            variants.add(capitalized)
            
        return list(variants)

    def _whitespace_mutations(self, payload: str) -> List[str]:
        """Generate whitespace mutations."""
        variants = set()
        
        whitespace_chars = ["\t", "\n", "\r", "\x0b", "\x0c", "/**/", "/*!*/"]
        
        for ws in whitespace_chars:
            # Replace spaces
            if " " in payload:
                variant = payload.replace(" ", ws)
                variants.add(variant)
                
            # Add extra whitespace
            if len(payload) > 1:
                insert_pos = random.randint(1, len(payload) - 1)
                variant = payload[:insert_pos] + ws + payload[insert_pos:]
                variants.add(variant)
                
        # Multiple spaces
        if " " in payload:
            variant = payload.replace(" ", "  ")
            variants.add(variant)
            variant = payload.replace(" ", "   ")
            variants.add(variant)
            
        return list(variants)

    def _null_byte_mutations(self, payload: str) -> List[str]:
        """Generate null byte mutations (use with caution)."""
        variants = set()
        
        null_bytes = ["\x00", "%00", "\\x00", "\\0"]
        keywords = ["script", "select", "union", "or", "and", "from", "where"]
        
        for keyword in keywords:
            if keyword in payload.lower():
                for null_byte in null_bytes:
                    variant = payload.lower().replace(keyword, keyword[:-1] + null_byte + keyword[-1])
                    variants.add(variant)
                    
        return list(variants)

    def _unicode_mutations(self, payload: str) -> List[str]:
        """Generate Unicode mutations."""
        variants = set()
        
        unicode_subs = {
            "<": ["\u003c", "\uff1c", "\ufe64"],
            ">": ["\u003e", "\uff1e", "\ufe65"],
            "'": ["\u0027", "\uff07", "\u02b9"],
            "\"": ["\u0022", "\uff02"],
            " ": ["\u00a0", "\u2000", "\u2001", "\u2002", "\u2003", "\u2004"],
            "/": ["\u2044", "\u2215", "\uff0f"],
            "\\": ["\u2216", "\uff3c"],
        }
        
        for char, replacements in unicode_subs.items():
            if char in payload:
                for replacement in replacements:
                    variant = payload.replace(char, replacement)
                    variants.add(variant)
                    
        # Full width characters
        full_width = ''.join(
            chr(ord(c) + 0xfee0) if 0x21 <= ord(c) <= 0x7e else c 
            for c in payload
        )
        if full_width != payload:
            variants.add(full_width)
            
        return list(variants)

    def _hex_mutations(self, payload: str) -> List[str]:
        """Generate hex encoding mutations."""
        variants = set()
        
        hex_patterns = {
            "SELECT": "0x53454c454354",
            "UNION": "0x554e494f4e",
            "OR": "0x4f52",
            "AND": "0x414e44",
            "FROM": "0x46524f4d",
            "WHERE": "0x5748455245",
        }
        
        for text, hex_val in hex_patterns.items():
            if text in payload.upper():
                variant = payload.upper().replace(text, hex_val)
                variants.add(variant)
                
        # Hex encode entire payload
        try:
            hex_full = payload.encode().hex()
            variants.add(hex_full)
        except UnicodeEncodeError:
            pass
            
        return list(variants)

    def _utf16_mutations(self, payload: str) -> List[str]:
        """Generate UTF-16 encoding mutations."""
        variants = set()
        
        try:
            # UTF-16 little endian with BOM
            utf16_le = payload.encode('utf-16-le').hex()
            variants.add(utf16_le)
            
            # UTF-16 big endian with BOM
            utf16_be = payload.encode('utf-16-be').hex()
            variants.add(utf16_be)
            
        except UnicodeEncodeError:
            pass
            
        return list(variants)

    def _utf32_mutations(self, payload: str) -> List[str]:
        """Generate UTF-32 encoding mutations."""
        variants = set()
        
        try:
            # UTF-32 encoding
            utf32 = payload.encode('utf-32').hex()
            variants.add(utf32)
            
        except UnicodeEncodeError:
            pass
            
        return list(variants)

    def _string_split_mutations(self, payload: str, context: PayloadContext) -> List[str]:
        """Generate string splitting mutations."""
        variants = set()
        
        if context == PayloadContext.SQL:
            # SQL string concatenation
            if len(payload) > 2:
                split_point = len(payload) // 2
                part1 = payload[:split_point]
                part2 = payload[split_point:]
                variant = f"{part1}'+'{part2}"
                variants.add(variant)
                variant = f"{part1}||'{part2}"
                variants.add(variant)
                
        elif context == PayloadContext.XSS:
            # JavaScript string concatenation
            if len(payload) > 2:
                split_point = len(payload) // 2
                part1 = payload[:split_point]
                part2 = payload[split_point:]
                variant = f"{part1}+{part2}"
                variants.add(variant)
                variant = f"{part1}{{+}}{part2}"
                variants.add(variant)
                
        return list(variants)

    def _variable_obfuscation_mutations(self, payload: str, context: PayloadContext) -> List[str]:
        """Generate variable obfuscation mutations."""
        variants = set()
        
        if context == PayloadContext.XSS:
            # JavaScript variable obfuscation
            js_obfuscations = [
                ("alert", "al"+"ert"),
                ("document", "doc"+"ument"),
                ("window", "win"+"dow"),
                ("eval", "ev"+"al"),
            ]
            
            for old, new in js_obfuscations:
                if old in payload:
                    variant = payload.replace(old, new)
                    variants.add(variant)
                    
        return list(variants)

    def _comment_variation_mutations(self, payload: str, context: PayloadContext) -> List[str]:
        """Generate comment variation mutations."""
        variants = set()
        
        comment_patterns = []
        
        if context == PayloadContext.SQL:
            comment_patterns = ["/*! */", "/*!12345*/", "-- ", "#", "/*", "*/"]
        elif context == PayloadContext.XSS:
            comment_patterns = ["<!--", "-->", "/*", "*/", "//"]
            
        for comment in comment_patterns:
            # Add comments around payload
            variant = f"{comment}{payload}{comment}"
            variants.add(variant)
            
            # Insert comments in the middle
            if len(payload) > 2:
                insert_pos = len(payload) // 2
                variant = payload[:insert_pos] + comment + payload[insert_pos:]
                variants.add(variant)
                
        return list(variants)

    def get_random_mutation(self, payload: str, context: Optional[PayloadContext] = None) -> str:
        """
        Return a single random mutation of the payload.
        
        Args:
            payload: The original payload
            context: Optional context for context-aware mutation
            
        Returns:
            A randomly mutated payload variant
        """
        if context is None:
            context = self.config["default_context"]
            
        techniques = self.config["context_specific_techniques"][context]
        
        # Try several techniques until we get a valid mutation
        for _ in range(10):  # Limit attempts
            technique = random.choice(techniques)
            variants = self._apply_technique(payload, technique, context)
            if variants:
                return random.choice(variants)
                
        return payload

    def get_context_for_payload(self, payload: str) -> PayloadContext:
        """
        Automatically detect the context of a payload.
        
        Args:
            payload: The payload to analyze
            
        Returns:
            Detected payload context
        """
        payload_lower = payload.lower()
        
        if any(sql_keyword in payload_lower for sql_keyword in 
               ["select", "union", "insert", "update", "delete", "from", "where"]):
            return PayloadContext.SQL
            
        elif any(xss_keyword in payload_lower for xss_keyword in
                ["script", "alert", "onerror", "onload", "javascript:"]):
            return PayloadContext.XSS
            
        elif any(cmd_keyword in payload_lower for cmd_keyword in
                [";", "|", "&", "`", "$(", "whoami", "id", "ls", "dir"]):
            return PayloadContext.COMMAND
            
        elif any(path_keyword in payload_lower for path_keyword in
                ["../", "..\\", "/etc/", "/bin/", "c:\\", "win.ini"]):
            return PayloadContext.PATH
            
        elif any(xxe_keyword in payload_lower for xxe_keyword in
                ["<!entity", "<?xml", "system", "file://"]):
            return PayloadContext.XXE
            
        else:
            return PayloadContext.GENERAL

# Legacy class for backward compatibility
class LegacyPayloadMutator:
    def mutate(self, payload: str) -> list:
        """Legacy mutate method for backward compatibility."""
        mutator = PayloadMutator()
        return mutator.mutate(payload, PayloadContext.GENERAL)
    
    def get_random_mutation(self, payload: str) -> str:
        """Legacy get_random_mutation method for backward compatibility."""
        mutator = PayloadMutator()
        return mutator.get_random_mutation(payload, PayloadContext.GENERAL)

# Global instance for simple usage
_global_mutator = PayloadMutator()

def mutate(payload: str) -> list:
    """Global mutate function for backward compatibility."""
    return _global_mutator.mutate(payload)

def get_random_mutation(payload: str) -> str:
    """Global get_random_mutation function for backward compatibility."""
    return _global_mutator.get_random_mutation(payload)
