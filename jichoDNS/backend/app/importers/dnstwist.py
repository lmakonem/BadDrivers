"""
DNSTwist-based typosquatting detector.

Uses dnstwist to generate and check permutations of African brand domains.
"""

import asyncio
import subprocess
import json
from datetime import datetime
from typing import List, Any, Optional
import shutil

from .base import BaseImporter, Indicator, IndicatorType, ThreatType


class DNSTwistImporter(BaseImporter):
    """
    Detect typosquatting domains targeting African brands.
    
    Uses dnstwist to generate domain permutations and checks for registered ones.
    
    Updates: Every 6 hours (resource intensive)
    Content: Registered domains that may be impersonating African brands
    
    Requires dnstwist to be installed: pip install dnstwist
    """
    
    name = "dnstwist"
    update_interval_minutes = 360  # Every 6 hours
    
    # Priority African domains to monitor
    MONITORED_DOMAINS = [
        # Mobile Money & Payments - Kenya
        "mpesa.com",
        "safaricom.co.ke",
        "equitybank.co.ke",
        "kcbgroup.com",
        
        # Mobile Money - Other Africa
        "mtn.com",
        "airtel.africa",
        "vodacom.co.za",
        "orange.com",
        
        # South African Banks
        "standardbank.co.za",
        "fnb.co.za",
        "nedbank.co.za",
        "absa.co.za",
        "capitecbank.co.za",
        
        # E-commerce
        "jumia.com",
        "takealot.com",
        
        # Pan-African
        "ecobank.com",
        "stanbicbank.com",
    ]
    
    def __init__(self):
        super().__init__()
        self.dnstwist_available = shutil.which("dnstwist") is not None
    
    async def fetch(self) -> Any:
        """Run dnstwist for each monitored domain."""
        if not self.dnstwist_available:
            self.logger.warning("dnstwist not installed, trying Python module")
        
        all_results = []
        
        # Limit to first 5 domains per run to avoid overloading
        domains_to_check = self.MONITORED_DOMAINS[:5]
        
        for domain in domains_to_check:
            try:
                results = await self._run_dnstwist(domain)
                all_results.extend(results)
            except Exception as e:
                self.logger.warning(f"Error running dnstwist for {domain}: {e}")
                continue
        
        return all_results
    
    async def _run_dnstwist(self, domain: str) -> List[dict]:
        """Run dnstwist for a single domain."""
        # Try command line first
        if self.dnstwist_available:
            return await self._run_dnstwist_cli(domain)
        else:
            return await self._run_dnstwist_module(domain)
    
    async def _run_dnstwist_cli(self, domain: str) -> List[dict]:
        """Run dnstwist CLI."""
        cmd = [
            "dnstwist",
            "--registered",  # Only show registered domains
            "--format", "json",
            "--threads", "10",
            domain
        ]
        
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        
        stdout, stderr = await asyncio.wait_for(
            process.communicate(),
            timeout=300  # 5 minute timeout per domain
        )
        
        if process.returncode != 0:
            self.logger.warning(f"dnstwist error for {domain}: {stderr.decode()}")
            return []
        
        try:
            results = json.loads(stdout.decode())
            for r in results:
                r["original_domain"] = domain
            return results
        except json.JSONDecodeError:
            self.logger.warning(f"Failed to parse dnstwist output for {domain}")
            return []
    
    async def _run_dnstwist_module(self, domain: str) -> List[dict]:
        """Run dnstwist as Python module."""
        try:
            import dnstwist
            
            # Run in thread pool since dnstwist is blocking
            loop = asyncio.get_event_loop()
            
            def run_twist():
                twist = dnstwist.DomainFuzz(domain)
                twist.generate()
                twist.check(registered=True, threads=10)
                return twist.domains
            
            results = await loop.run_in_executor(None, run_twist)
            
            # Convert to dict format
            return [
                {**d, "original_domain": domain}
                for d in results
                if d.get("dns_a") or d.get("dns_aaaa") or d.get("dns_mx")
            ]
            
        except ImportError:
            self.logger.error("dnstwist module not installed")
            return []
        except Exception as e:
            self.logger.warning(f"Error running dnstwist module for {domain}: {e}")
            return []
    
    async def parse(self, raw_data: Any) -> List[Indicator]:
        """Parse dnstwist results."""
        indicators = []
        now = datetime.utcnow()
        seen = set()
        
        for item in raw_data:
            try:
                domain = item.get("domain", "").lower()
                fuzzer = item.get("fuzzer", "")
                original = item.get("original_domain", "")
                
                if not domain or domain == original:
                    continue
                
                if domain in seen:
                    continue
                seen.add(domain)
                
                # Check if it has DNS records (registered and active)
                has_dns = (
                    item.get("dns_a") or 
                    item.get("dns_aaaa") or 
                    item.get("dns_mx") or
                    item.get("dns_ns")
                )
                
                if not has_dns:
                    continue
                
                # Build tags
                tags = ["dnstwist", "typosquat", f"fuzzer:{fuzzer.lower()}"]
                
                # Extract brand from original domain
                brand = original.split(".")[0]
                tags.append(f"impersonates:{brand}")
                
                # Higher confidence if domain looks very similar
                confidence = self._calculate_confidence(item)
                
                indicators.append(Indicator(
                    indicator=domain,
                    indicator_type=IndicatorType.DOMAIN,
                    threat_type=ThreatType.PHISHING,
                    source=self.name,
                    source_url=f"https://dnstwist.it/?domain={original}",
                    confidence=confidence,
                    tags=tags,
                    first_seen=now,
                    last_seen=now,
                    metadata={
                        "original_domain": original,
                        "fuzzer": fuzzer,
                        "dns_a": item.get("dns_a"),
                        "dns_aaaa": item.get("dns_aaaa"),
                        "dns_mx": item.get("dns_mx"),
                        "dns_ns": item.get("dns_ns"),
                        "geoip_country": item.get("geoip_country"),
                        "whois_registrar": item.get("whois_registrar"),
                        "whois_created": item.get("whois_created"),
                    },
                ))
                
            except Exception as e:
                self.logger.warning(f"Error parsing dnstwist item: {e}")
                continue
        
        return indicators
    
    def _calculate_confidence(self, item: dict) -> float:
        """Calculate confidence score based on similarity and indicators."""
        confidence = 0.5
        
        fuzzer = item.get("fuzzer", "").lower()
        
        # Higher confidence for certain fuzzer types
        high_risk_fuzzers = ["homoglyph", "hyphenation", "insertion", "omission"]
        medium_risk_fuzzers = ["replacement", "transposition", "vowel-swap"]
        
        if fuzzer in high_risk_fuzzers:
            confidence = 0.85
        elif fuzzer in medium_risk_fuzzers:
            confidence = 0.75
        else:
            confidence = 0.65
        
        # Increase confidence if recently registered
        if item.get("whois_created"):
            # TODO: Parse date and check if < 30 days old
            confidence = min(confidence + 0.1, 0.95)
        
        # Increase if has MX record (may be used for phishing emails)
        if item.get("dns_mx"):
            confidence = min(confidence + 0.05, 0.95)
        
        return confidence
