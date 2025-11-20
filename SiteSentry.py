#!/usr/bin/env python3
"""
Advanced Website Footprinting & Security Assessment Tool
Enhanced with Deep Technology Fingerprinting, Security Analysis, Cloud Footprinting, and Network Reconnaissance
"""

import argparse
import subprocess
import sys
import json
import socket
import whois
import dns.resolver
import dns.zone
import dns.query
import requests
import ssl
import datetime
from urllib.parse import urlparse, urljoin, quote
import concurrent.futures
import time
import re
import os
import threading
from typing import List, Dict, Any, Optional, Tuple
import smtplib
import logging
import xml.etree.ElementTree as ET
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import hashlib
import base64
import random
import string

# Suppress SSL warnings
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('footprinting.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class AdvancedWebsiteFootprinter:
    def __init__(self, domain: str, wordlist: Optional[str] = None, timeout: int = 10, 
                 max_retries: int = 3, scan_ports: bool = False, threads: int = 50):
        self.original_domain = domain
        self.domain = self.clean_domain(domain)
        self.safe_filename = self.create_safe_filename(self.domain)
        self.wordlist = wordlist
        self.timeout = timeout
        self.max_retries = max_retries
        self.scan_ports = scan_ports
        self.threads = threads
        self.results = {}
        self.session = self._create_session()
        
        # Configure DNS resolver
        dns.resolver.default_resolver = dns.resolver.Resolver(configure=False)
        dns.resolver.default_resolver.nameservers = ['8.8.8.8', '1.1.1.1', '8.8.4.4']
    
    def _create_session(self) -> requests.Session:
        """Create requests session with retry logic and timeouts"""
        session = requests.Session()
        
        retry_strategy = Retry(
            total=self.max_retries,
            backoff_factor=0.5,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        session.timeout = self.timeout
        return session
    
    def clean_domain(self, domain: str) -> str:
        """Remove http/https/www and clean the domain"""
        domain = domain.lower()
        domain = re.sub(r'^https?://', '', domain)
        domain = re.sub(r'^www\.', '', domain)
        domain = domain.rstrip('/')
        return domain
    
    def create_safe_filename(self, domain: str) -> str:
        """Create a safe filename from domain"""
        safe_name = re.sub(r'[^a-zA-Z0-9.]', '_', domain)
        safe_name = re.sub(r'_+', '_', safe_name)
        safe_name = safe_name.strip('_.')
        return safe_name
    
    def execute_with_retry(self, func, *args, **kwargs):
        """Execute a function with retry logic"""
        for attempt in range(self.max_retries):
            try:
                return func(*args, **kwargs)
            except (requests.exceptions.RequestException, 
                    socket.timeout, 
                    dns.resolver.Timeout,
                    ConnectionError) as e:
                if attempt == self.max_retries - 1:
                    raise e
                time.sleep(1 * (attempt + 1))
        return None

    # === ENHANCED WILDCARD DNS CHECK ===
    
    def wildcard_dns_check(self) -> bool:
        """Check if wildcard DNS is enabled for the domain"""
        logger.info("Performing wildcard DNS check")
        try:
            # Generate a shorter random subdomain that likely doesn't exist
            random_subdomain = f"test{random.randint(10000, 99999)}.{self.domain}"
            try:
                socket.gethostbyname(random_subdomain)
                logger.warning(f"Wildcard DNS detected for {self.domain}")
                return True
            except socket.gaierror:
                logger.info("No wildcard DNS detected")
                return False
        except Exception as e:
            logger.error(f"Wildcard DNS check failed: {e}")
            return False

    # === DEEP TECHNOLOGY FINGERPRINTING ===
    
    def deep_technology_fingerprinting(self) -> Dict[str, Any]:
        """Perform deep technology stack and version detection"""
        logger.info("Performing deep technology fingerprinting")
        
        technologies = {
            'cms': {},
            'frameworks': {},
            'programming_languages': {},
            'web_servers': {},
            'javascript_libraries': {},
            'analytics_tools': {},
            'caching_systems': {},
            'operating_systems': {}
        }
        
        try:
            response = self.session.get(f"https://{self.domain}", timeout=self.timeout, verify=False)
            content = response.text
            headers = response.headers
            
            # Analyze HTML content for technology signatures
            self._analyze_html_signatures(content, technologies)
            
            # Analyze HTTP headers for technology clues
            self._analyze_header_signatures(headers, technologies)
            
            # Check common technology-specific paths
            self._check_technology_paths(technologies)
            
            # Analyze JavaScript and CSS for library signatures
            self._analyze_asset_signatures(content, technologies)
            
            # Clean up empty categories
            technologies = {k: v for k, v in technologies.items() if v}
            
            self.results['deep_technologies'] = technologies
            return technologies
            
        except Exception as e:
            error_msg = f"Deep technology fingerprinting failed: {str(e)}"
            logger.error(error_msg)
            return {"error": error_msg}
    
    def _analyze_html_signatures(self, content: str, technologies: Dict[str, Any]):
        """Analyze HTML content for technology signatures"""
        
        # CMS Detection
        cms_signatures = {
            'WordPress': [
                (r'wp-content|wp-includes|wordpress', None),
                (r'content="WordPress (\d+\.\d+(?:\.\d+)?)"', 'version'),
                (r'/wp-json/', None)
            ],
            'Drupal': [
                (r'sites/all/|drupal\.js', None),
                (r'content="Drupal (\d+\.\d+(?:\.\d+)?)"', 'version'),
                (r'Drupal\.settings', None)
            ],
            'Joomla': [
                (r'/media/jui/|/media/system/', None),
                (r'content="Joomla!? (\d+\.\d+(?:\.\d+)?)"', 'version')
            ],
            'Magento': [
                (r'Mage\.|/js/mage/', None),
                (r'content="Magento (\d+\.\d+(?:\.\d+)?)"', 'version')
            ],
            'Shopify': [
                (r'shopify', None),
                (r'cdn\.shopify\.com', None)
            ]
        }
        
        for cms, signatures in cms_signatures.items():
            for pattern, version_group in signatures:
                matches = re.search(pattern, content, re.IGNORECASE)
                if matches:
                    technologies['cms'][cms] = {'detected': True}
                    if version_group and matches.groups():
                        technologies['cms'][cms]['version'] = matches.group(1)
                    break
    
    def _analyze_header_signatures(self, headers: Dict[str, str], technologies: Dict[str, Any]):
        """Analyze HTTP headers for technology signatures"""
        
        # Web Server Detection
        server_headers = headers.get('Server', '')
        if 'nginx' in server_headers.lower():
            technologies['web_servers']['Nginx'] = {'version': self._extract_version(server_headers)}
        elif 'apache' in server_headers.lower():
            technologies['web_servers']['Apache'] = {'version': self._extract_version(server_headers)}
        elif 'iis' in server_headers.lower():
            technologies['web_servers']['IIS'] = {'version': self._extract_version(server_headers)}
        
        # Framework detection from headers
        powered_by = headers.get('X-Powered-By', '')
        if 'php' in powered_by.lower():
            technologies['programming_languages']['PHP'] = {'version': self._extract_version(powered_by)}
        elif 'asp.net' in powered_by.lower():
            technologies['frameworks']['ASP.NET'] = {'version': self._extract_version(powered_by)}
    
    def _extract_version(self, text: str) -> str:
        """Extract version number from text"""
        version_match = re.search(r'(\d+\.\d+(?:\.\d+)?)', text)
        return version_match.group(1) if version_match else 'Unknown'
    
    def _check_technology_paths(self, technologies: Dict[str, Any]):
        """Check common technology-specific paths"""
        
        tech_paths = {
            'WordPress': ['/wp-admin/', '/wp-login.php', '/wp-content/'],
            'Drupal': ['/user/login', '/admin/', '/sites/all/'],
            'Joomla': ['/administrator/', '/media/system/'],
            'Magento': ['/admin/', '/js/mage/'],
            'phpMyAdmin': ['/phpmyadmin/'],
            'cPanel': ['/cpanel/', '/whm/']
        }
        
        for tech, paths in tech_paths.items():
            for path in paths:
                try:
                    response = self.session.head(f"https://{self.domain}{path}", timeout=5, verify=False)
                    if response.status_code < 400:
                        if tech not in technologies.get('admin_interfaces', {}):
                            technologies.setdefault('admin_interfaces', {})[tech] = []
                        technologies['admin_interfaces'][tech].append(path)
                except:
                    pass
    
    def _analyze_asset_signatures(self, content: str, technologies: Dict[str, Any]):
        """Analyze JavaScript and CSS for library signatures"""
        
        # JavaScript library detection
        js_libraries = {
            'jQuery': [r'jquery[.-](\d+\.\d+\.\d+)', r'/jquery(?:\.min)?\.js'],
            'React': [r'react@(\d+\.\d+\.\d+)', r'React\.version'],
            'Vue.js': [r'vue@(\d+\.\d+\.\d+)', r'Vue\.version'],
            'Angular': [r'angular[.-](\d+\.\d+\.\d+)', r'ng-version'],
            'Bootstrap': [r'bootstrap[.-](\d+\.\d+\.\d+)', r'/bootstrap(?:\.min)?\.js']
        }
        
        for lib, patterns in js_libraries.items():
            for pattern in patterns:
                matches = re.search(pattern, content, re.IGNORECASE)
                if matches:
                    technologies['javascript_libraries'][lib] = {'detected': True}
                    if matches.groups():
                        technologies['javascript_libraries'][lib]['version'] = matches.group(1)
                    break

    # === SECURITY HEADER ANALYSIS ===
    
    def security_header_analysis(self) -> Dict[str, Any]:
        """Perform comprehensive security header analysis"""
        logger.info("Analyzing security headers")
        
        security_analysis = {
            'missing_headers': [],
            'weak_directives': {},
            'vulnerabilities': [],
            'score': 0,
            'recommendations': []
        }
        
        try:
            response = self.session.get(f"https://{self.domain}", timeout=self.timeout, verify=False)
            headers = response.headers
            
            # Check essential security headers
            self._analyze_hsts_header(headers, security_analysis)
            self._analyze_csp_header(headers, security_analysis)
            self._analyze_cors_headers(headers, security_analysis)
            self._analyze_other_security_headers(headers, security_analysis)
            
            # Calculate security score
            security_analysis['score'] = self._calculate_security_score(security_analysis)
            
            self.results['security_headers'] = security_analysis
            return security_analysis
            
        except Exception as e:
            error_msg = f"Security header analysis failed: {str(e)}"
            logger.error(error_msg)
            return {"error": error_msg}
    
    def _analyze_hsts_header(self, headers: Dict[str, str], analysis: Dict[str, Any]):
        """Analyze HSTS header"""
        hsts = headers.get('Strict-Transport-Security', '')
        
        if not hsts:
            analysis['missing_headers'].append('Strict-Transport-Security')
            analysis['recommendations'].append('Implement HSTS with max-age of at least 31536000 and includeSubDomains')
            return
        
        # Check HSTS directives
        directives = {}
        for directive in hsts.split(';'):
            if '=' in directive:
                key, value = directive.strip().split('=', 1)
                directives[key] = value
            else:
                directives[directive.strip()] = True
        
        # Analyze HSTS configuration
        if 'max-age' not in directives:
            analysis['vulnerabilities'].append('HSTS missing max-age directive')
        elif int(directives.get('max-age', 0)) < 31536000:
            analysis['weak_directives']['HSTS'] = 'max-age should be at least 31536000 (1 year)'
        
        if 'includeSubDomains' not in directives:
            analysis['recommendations'].append('Add includeSubDomains to HSTS header')
        
        if 'preload' not in directives:
            analysis['recommendations'].append('Consider adding preload directive for HSTS preloading')
    
    def _analyze_csp_header(self, headers: Dict[str, str], analysis: Dict[str, Any]):
        """Analyze Content Security Policy header"""
        csp = headers.get('Content-Security-Policy', '')
        
        if not csp:
            analysis['missing_headers'].append('Content-Security-Policy')
            analysis['recommendations'].append('Implement Content Security Policy to prevent XSS attacks')
            return
        
        # Basic CSP analysis
        if "unsafe-inline" in csp or "unsafe-eval" in csp:
            analysis['weak_directives']['CSP'] = 'CSP contains unsafe directives (unsafe-inline/unsafe-eval)'
        
        if "default-src 'none'" not in csp:
            analysis['recommendations'].append('Consider using default-src none as base CSP policy')
    
    def _analyze_cors_headers(self, headers: Dict[str, str], analysis: Dict[str, Any]):
        """Analyze CORS headers for misconfigurations"""
        acao = headers.get('Access-Control-Allow-Origin', '')
        acac = headers.get('Access-Control-Allow-Credentials', '')
        
        if acao == '*':
            if acac.lower() == 'true':
                analysis['vulnerabilities'].append('CORS misconfiguration: Allow-Origin: * with Allow-Credentials: true')
            else:
                analysis['weak_directives']['CORS'] = 'CORS allows all origins (*)'
    
    def _analyze_other_security_headers(self, headers: Dict[str, str], analysis: Dict[str, Any]):
        """Analyze other security headers"""
        security_headers = {
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': ['DENY', 'SAMEORIGIN'],
            'X-XSS-Protection': '1; mode=block',
            'Referrer-Policy': True,
            'Permissions-Policy': True
        }
        
        for header, expected in security_headers.items():
            value = headers.get(header, '')
            if not value:
                analysis['missing_headers'].append(header)
            elif expected is not True and value != expected:
                if isinstance(expected, list):
                    if value not in expected:
                        analysis['weak_directives'][header] = f'Expected one of {expected}, got {value}'
                else:
                    analysis['weak_directives'][header] = f'Expected {expected}, got {value}'
    
    def _calculate_security_score(self, analysis: Dict[str, Any]) -> int:
        """Calculate security header score (0-100)"""
        base_score = 100
        penalties = len(analysis['missing_headers']) * 10
        penalties += len(analysis['weak_directives']) * 5
        penalties += len(analysis['vulnerabilities']) * 20
        
        return max(0, base_score - penalties)

    # === CORS MISCONFIGURATION CHECKS ===
    
    def cors_misconfiguration_check(self) -> Dict[str, Any]:
        """Test for CORS misconfigurations"""
        logger.info("Testing for CORS misconfigurations")
        
        cors_tests = {
            'null_origin': self._test_cors_origin('null'),
            'wildcard_origin': self._test_cors_origin('*'),
            'domain_origin': self._test_cors_origin(f'https://{self.domain}'),
            'subdomain_origin': self._test_cors_origin(f'https://subdomain.{self.domain}'),
            'http_origin': self._test_cors_origin(f'http://{self.domain}'),
            'evil_origin': self._test_cors_origin('https://evil.com')
        }
        
        vulnerabilities = []
        for test_name, result in cors_tests.items():
            if result.get('vulnerable'):
                vulnerabilities.append({
                    'type': test_name,
                    'details': result
                })
        
        cors_analysis = {
            'tests_performed': cors_tests,
            'vulnerabilities_found': vulnerabilities,
            'risk_level': 'HIGH' if vulnerabilities else 'LOW'
        }
        
        self.results['cors_analysis'] = cors_analysis
        return cors_analysis
    
    def _test_cors_origin(self, origin: str) -> Dict[str, Any]:
        """Test specific origin for CORS misconfiguration"""
        try:
            headers = {'Origin': origin}
            response = self.session.options(
                f"https://{self.domain}",
                headers=headers,
                timeout=self.timeout,
                verify=False
            )
            
            acao = response.headers.get('Access-Control-Allow-Origin', '')
            acac = response.headers.get('Access-Control-Allow-Credentials', '')
            
            vulnerable = False
            if origin == 'null' and acao == 'null' and acac == 'true':
                vulnerable = True
            elif origin == '*' and acao == '*':
                vulnerable = True
            elif acao == origin and acac == 'true':
                vulnerable = True
            
            return {
                'origin': origin,
                'acao': acao,
                'acac': acac,
                'vulnerable': vulnerable
            }
            
        except Exception as e:
            return {
                'origin': origin,
                'error': str(e),
                'vulnerable': False
            }

    # === EXPOSURE & CLOUD FOOTPRINTING ===
    
    def exposure_cloud_footprinting(self) -> Dict[str, Any]:
        """Perform exposure analysis and cloud bucket enumeration"""
        logger.info("Performing exposure and cloud footprinting")
        
        exposure_data = {
            'google_dorks': self._generate_google_dorks(),
            'cloud_buckets': self._enumerate_cloud_buckets(),
            'exposed_files': self._check_common_exposed_files(),
            'document_metadata': {}
        }
        
        self.results['exposure_analysis'] = exposure_data
        return exposure_data
    
    def _generate_google_dorks(self) -> List[Dict[str, str]]:
        """Generate Google dorks for the target domain"""
        dorks = [
            {
                'type': 'Configuration Files',
                'dork': f'site:{self.domain} ext:xml | ext:conf | ext:cnf | ext:reg | ext:inf | ext:rdp | ext:cfg | ext:txt | ext:ora | ext:ini',
                'description': 'Find configuration files'
            },
            {
                'type': 'Database Files',
                'dork': f'site:{self.domain} ext:sql | ext:dbf | ext:mdb',
                'description': 'Find database files'
            },
            {
                'type': 'Log Files',
                'dork': f'site:{self.domain} ext:log',
                'description': 'Find log files'
            },
            {
                'type': 'Backup Files',
                'dork': f'site:{self.domain} ext:bkf | ext:bkp | ext:bak | ext:old | ext:backup',
                'description': 'Find backup files'
            },
            {
                'type': 'Admin Pages',
                'dork': f'site:{self.domain} inurl:admin | inurl:login | inurl:dashboard',
                'description': 'Find admin interfaces'
            },
            {
                'type': 'Documentation',
                'dork': f'site:{self.domain} ext:doc | ext:docx | ext:odt | ext:pdf | ext:rtf | ext:sxw | ext:psw | ext:ppt | ext:pptx | ext:pps | ext:csv',
                'description': 'Find documents'
            },
            {
                'type': 'Email Lists',
                'dork': f'site:{self.domain} intext:@{self.domain}',
                'description': 'Find email addresses'
            },
            {
                'type': 'Open Directories',
                'dork': f'site:{self.domain} "index of"',
                'description': 'Find open directories'
            }
        ]
        
        return dorks
    
    def _enumerate_cloud_buckets(self) -> Dict[str, List[str]]:
        """Enumerate potential cloud storage buckets"""
        buckets = {
            'aws_s3': [],
            'google_cloud': [],
            'azure_blob': []
        }
        
        # Generate bucket name variations
        domain_parts = self.domain.replace('.', '-').split('-')
        base_names = [
            self.domain,
            self.domain.replace('.', '-'),
            self.domain.replace('.', ''),
            f"{self.domain}-assets",
            f"{self.domain}-storage",
            f"{self.domain}-media",
            f"{self.domain}-backup",
            f"www-{self.domain}",
            f"prod-{self.domain}",
            f"staging-{self.domain}",
            f"dev-{self.domain}",
            f"test-{self.domain}"
        ]
        
        # Add domain part combinations
        if len(domain_parts) > 1:
            base_names.extend([
                f"{domain_parts[0]}-{domain_parts[1]}",
                f"{domain_parts[0]}{domain_parts[1]}",
                f"{domain_parts[-2]}-{domain_parts[-1]}"
            ])
        
        # Test AWS S3 buckets
        for name in base_names:
            buckets['aws_s3'].extend([
                f"{name}",
                f"{name}-assets",
                f"{name}-media",
                f"{name}-storage",
                f"prod-{name}",
                f"staging-{name}",
                f"dev-{name}"
            ])
        
        # Test Google Cloud Storage
        for name in base_names:
            buckets['google_cloud'].append(name)
        
        # Test Azure Blob Storage
        for name in base_names:
            buckets['azure_blob'].append(name)
        
        return buckets
    
    def _check_common_exposed_files(self) -> Dict[str, Any]:
        """Check for common exposed files"""
        exposed_files = {}
        common_files = [
            '/.git/config',
            '/.env',
            '/config.json',
            '/database.json',
            '/backup.zip',
            '/dump.sql',
            '/wp-config.php',
            '/config.php',
            '/settings.py',
            '/.htaccess',
            '/web.config',
            '/robots.txt',
            '/sitemap.xml',
            '/crossdomain.xml',
            '/clientaccesspolicy.xml'
        ]
        
        for file_path in common_files:
            try:
                response = self.session.head(
                    f"https://{self.domain}{file_path}",
                    timeout=5,
                    verify=False
                )
                if response.status_code == 200:
                    exposed_files[file_path] = {
                        'status': 'EXPOSED',
                        'size': response.headers.get('Content-Length', 'Unknown')
                    }
            except:
                pass
        
        return exposed_files

    # === ADVANCED DNS HARVESTING ===
    
    def advanced_dns_harvesting(self) -> Dict[str, Any]:
        """Perform advanced DNS analysis including SPF/DMARC"""
        logger.info("Performing advanced DNS harvesting")
        
        dns_analysis = {
            'spf_records': self._analyze_spf_records(),
            'dmarc_records': self._analyze_dmarc_records(),
            'dkim_records': self._check_dkim_records(),
            'dns_enumeration': self._perform_dns_enumeration(),
            'dns_zone_transfer': self._test_zone_transfer()
        }
        
        self.results['advanced_dns'] = dns_analysis
        return dns_analysis
    
    def _analyze_spf_records(self) -> Dict[str, Any]:
        """Analyze SPF records for email security"""
        try:
            answers = dns.resolver.resolve(self.domain, 'TXT')
            spf_record = None
            
            for rdata in answers:
                if 'v=spf1' in str(rdata):
                    spf_record = str(rdata)
                    break
            
            if not spf_record:
                return {'exists': False, 'risk': 'HIGH', 'message': 'No SPF record found'}
            
            analysis = {
                'exists': True,
                'record': spf_record,
                'mechanisms': [],
                'modifiers': [],
                'risk': 'LOW'
            }
            
            # Parse SPF mechanisms
            mechanisms = spf_record.split(' ')[1:]  # Skip v=spf1
            for mechanism in mechanisms:
                if mechanism.startswith('+') or not mechanism.startswith(('-', '~', '?')):
                    analysis['mechanisms'].append(mechanism)
                elif mechanism.startswith(('+all', 'all')):
                    analysis['risk'] = 'HIGH'
                    analysis['message'] = 'SPF record ends with +all (too permissive)'
                elif mechanism.startswith(('~all', '-all')):
                    analysis['risk'] = 'LOW'
                elif mechanism.startswith('?all'):
                    analysis['risk'] = 'MEDIUM'
                    analysis['message'] = 'SPF record ends with ?all (neutral)'
            
            return analysis
            
        except Exception as e:
            return {'exists': False, 'error': str(e)}
    
    def _analyze_dmarc_records(self) -> Dict[str, Any]:
        """Analyze DMARC records for email security"""
        try:
            answers = dns.resolver.resolve(f'_dmarc.{self.domain}', 'TXT')
            dmarc_record = None
            
            for rdata in answers:
                if 'v=DMARC1' in str(rdata):
                    dmarc_record = str(rdata)
                    break
            
            if not dmarc_record:
                return {'exists': False, 'risk': 'HIGH', 'message': 'No DMARC record found'}
            
            analysis = {
                'exists': True,
                'record': dmarc_record,
                'policy': 'none',
                'subdomain_policy': 'none',
                'percentage': 100,
                'risk': 'LOW'
            }
            
            # Parse DMARC tags
            tags = dmarc_record.split(';')
            for tag in tags:
                if 'p=' in tag:
                    policy = tag.split('=')[1].strip()
                    analysis['policy'] = policy
                    if policy == 'none':
                        analysis['risk'] = 'MEDIUM'
                        analysis['message'] = 'DMARC policy is set to none (monitoring only)'
                elif 'sp=' in tag:
                    analysis['subdomain_policy'] = tag.split('=')[1].strip()
                elif 'pct=' in tag:
                    analysis['percentage'] = int(tag.split('=')[1].strip())
            
            return analysis
            
        except Exception as e:
            return {'exists': False, 'error': str(e)}
    
    def _check_dkim_records(self) -> Dict[str, Any]:
        """Check for DKIM records"""
        selectors = ['default', 'google', 'selector1', 'selector2', 'k1', 'dkim']
        dkim_records = {}
        
        for selector in selectors:
            try:
                answers = dns.resolver.resolve(f'{selector}._domainkey.{self.domain}', 'TXT')
                for rdata in answers:
                    if 'v=DKIM1' in str(rdata):
                        dkim_records[selector] = str(rdata)
            except:
                continue
        
        return {
            'exists': len(dkim_records) > 0,
            'records': dkim_records,
            'risk': 'HIGH' if not dkim_records else 'LOW'
        }
    
    def _perform_dns_enumeration(self) -> Dict[str, Any]:
        """Perform comprehensive DNS enumeration"""
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA', 'SRV', 'PTR']
        records = {}
        
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(self.domain, record_type)
                records[record_type] = [str(rdata) for rdata in answers]
            except Exception as e:
                records[record_type] = f"Error: {str(e)}"
        
        return records
    
    def _test_zone_transfer(self) -> Dict[str, Any]:
        """Test for DNS zone transfer vulnerability"""
        try:
            ns_records = dns.resolver.resolve(self.domain, 'NS')
            zone_transfer_results = {}
            
            for ns in ns_records:
                ns_server = str(ns).rstrip('.')
                try:
                    # Try zone transfer
                    transfer = dns.zone.from_xfr(dns.query.xfr(ns_server, self.domain))
                    if transfer:
                        zone_transfer_results[ns_server] = 'VULNERABLE'
                    else:
                        zone_transfer_results[ns_server] = 'Secure'
                except:
                    zone_transfer_results[ns_server] = 'Secure'
            
            return {
                'vulnerable': any(status == 'VULNERABLE' for status in zone_transfer_results.values()),
                'results': zone_transfer_results
            }
            
        except Exception as e:
            return {'error': str(e)}

    # === BASIC FOOTPRINTING METHODS ===
    
    def dns_lookup(self) -> Dict[str, Any]:
        """Perform comprehensive DNS lookups"""
        logger.info(f"Performing DNS lookups for {self.domain}")
        dns_results = {}
        
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
        
        for record_type in record_types:
            try:
                answers = self.execute_with_retry(dns.resolver.resolve, self.domain, record_type)
                dns_results[record_type] = [str(rdata) for rdata in answers]
            except Exception as e:
                dns_results[record_type] = f"Error: {str(e)}"
        
        self.results['dns'] = dns_results
        return dns_results
    
    def whois_lookup(self) -> Dict[str, Any]:
        """Perform WHOIS lookup"""
        logger.info(f"Performing WHOIS lookup for {self.domain}")
        try:
            whois_info = self.execute_with_retry(whois.whois, self.domain)
            self.results['whois'] = whois_info
            return whois_info
        except Exception as e:
            error_msg = f"WHOIS lookup failed: {str(e)}"
            self.results['whois'] = error_msg
            return {"error": error_msg}
    
    def geoip_asn_lookup(self) -> Dict[str, Any]:
        """Perform GeoIP and ASN lookup"""
        logger.info("Performing GeoIP/ASN lookup")
        try:
            # Using ipapi.co for GeoIP information
            ip = socket.gethostbyname(self.domain)
            response = self.session.get(f"http://ipapi.co/{ip}/json/", timeout=self.timeout)
            
            if response.status_code == 200:
                geo_data = response.json()
                geo_info = {
                    'ip': geo_data.get('ip'),
                    'city': geo_data.get('city'),
                    'region': geo_data.get('region'),
                    'country': geo_data.get('country_name'),
                    'latitude': geo_data.get('latitude'),
                    'longitude': geo_data.get('longitude'),
                    'asn': geo_data.get('asn'),
                    'org': geo_data.get('org'),
                    'isp': geo_data.get('org')
                }
                self.results['geoip_asn'] = geo_info
                return geo_info
            else:
                return {"error": f"GeoIP lookup failed with status {response.status_code}"}
                
        except Exception as e:
            error_msg = f"GeoIP/ASN lookup failed: {str(e)}"
            self.results['geoip_asn'] = {"error": error_msg}
            return {"error": error_msg}
    
    def email_enumeration(self) -> List[str]:
        """Enhanced email pattern enumeration"""
        logger.info(f"Performing email enumeration for {self.domain}")
        email_patterns = []
        
        # Common email patterns
        common_usernames = [
            'admin', 'administrator', 'webmaster', 'info', 'contact', 
            'support', 'help', 'sales', 'news', 'media', 'press',
            'security', 'hostmaster', 'postmaster', 'abuse', 'noc',
            'billing', 'accounts', 'finance', 'marketing', 'hr',
            'careers', 'jobs', 'legal', 'pr', 'media', 'press'
        ]
        
        # Department-based patterns
        departments = ['it', 'tech', 'engineering', 'dev', 'development', 'ops', 'operations']
        
        for username in common_usernames:
            email_patterns.append(f"{username}@{self.domain}")
        
        for dept in departments:
            email_patterns.extend([
                f"{dept}@{self.domain}",
                f"{dept}team@{self.domain}",
                f"team{dept}@{self.domain}"
            ])
        
        self.results['email_patterns'] = email_patterns
        return email_patterns
    
    def subdomain_discovery(self) -> List[str]:
        """Enhanced subdomain discovery with wildcard DNS check"""
        logger.info(f"Performing subdomain discovery for {self.domain}")
        
        # Check for wildcard DNS first
        has_wildcard = self.wildcard_dns_check()
        self.results['wildcard_dns'] = has_wildcard
        
        if has_wildcard:
            logger.warning("Wildcard DNS detected - subdomain discovery may yield false positives")
        
        subdomains = []
        wordlist = self.load_subdomain_wordlist()
        
        def check_subdomain(subdomain: str) -> Optional[str]:
            full_domain = f"{subdomain}.{self.domain}"
            try:
                ip = socket.gethostbyname(full_domain)
                # Additional verification for wildcard domains
                if has_wildcard:
                    # Check if the IP is different from the wildcard IP
                    wildcard_domain = f"test{random.randint(10000, 99999)}.{self.domain}"
                    try:
                        wildcard_ip = socket.gethostbyname(wildcard_domain)
                        if ip == wildcard_ip:
                            return None  # Likely a wildcard response
                    except:
                        pass
                return full_domain
            except socket.gaierror:
                return None
            except Exception as e:
                logger.debug(f"Error checking {full_domain}: {e}")
                return None
        
        # Use threading for faster subdomain discovery
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            futures = {executor.submit(check_subdomain, sub): sub for sub in wordlist}
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    subdomains.append(result)
                    logger.info(f"Discovered subdomain: {result}")
        
        self.results['subdomains'] = subdomains
        return subdomains
    
    def load_subdomain_wordlist(self) -> List[str]:
        """Load subdomain wordlist from file or use default"""
        if self.wordlist and os.path.exists(self.wordlist):
            try:
                with open(self.wordlist, 'r', encoding='utf-8', errors='ignore') as f:
                    wordlist = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                logger.info(f"Loaded {len(wordlist)} subdomains from {self.wordlist}")
                return wordlist
            except Exception as e:
                logger.error(f"Failed to load wordlist: {e}")
        
        # Default wordlist
        default_wordlist = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
            'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'm', 'imap', 'test',
            'ns', 'blog', 'pop3', 'dev', 'www2', 'admin', 'forum', 'news', 'vpn',
            'api', 'apps', 'search', 'cdn', 'remote', 'server', 'ns3', 'mail2', 'new',
            'support', 'mobile', 'static', 'docs', 'beta', 'shop', 'sql', 'secure',
            'demo', 'portal', 'video', 'email', 'images', 'img', 'download', 'dns',
            'media', 'help', 'code', 'live', 'stats', 'data', 'account', 'ad', 'admanager',
            'ads', 'adserver', 'adserver2', 'adserv', 'alpha', 'app', 'archive', 'backup',
            'backup2', 'crm', 'mssql', 'mysql', 'oracle', 'files', 'file', 'finance',
            'gateway', 'git', 'host', 'hosting', 'im', 'irc', 'list', 'lists', 'log',
            'logs', 'lync', 'lyncdiscover', 'monitor', 'old', 'owa', 'phone', 'photo',
            'photos', 'pic', 'pics', 'picture', 'pictures', 'proxy', 'router', 'rss',
            'sandbox', 'sharepoint', 'sip', 'site', 'sites', 'sms', 'smtp2', 'software',
            'stage', 'staging', 'stream', 'streaming', 'survey', 'surveys', 'test2',
            'testing', 'tube', 'tv', 'upload', 'uploads', 'videos', 'voice', 'voip',
            'web', 'web2', 'webaccess', 'webalizer', 'webconf', 'webinar', 'webserver',
            'website', 'whm', 'wiki', 'win', 'windows', 'wordpress', 'wp', 'xml', 'xmpp'
        ]
        logger.info(f"Using default wordlist with {len(default_wordlist)} subdomains")
        return default_wordlist

    # === MAIN EXECUTION ===
    
    def run_all_checks(self) -> Dict[str, Any]:
        """Execute all advanced footprinting checks"""
        logger.info(f"Starting comprehensive advanced footprinting for: {self.domain}")
        print("=" * 60)
        
        start_time = time.time()
        
        # Run all checks
        checks = [
            self.dns_lookup,
            self.whois_lookup,
            self.geoip_asn_lookup,
            self.email_enumeration,
            self.subdomain_discovery,
            self.deep_technology_fingerprinting,
            self.security_header_analysis,
            self.cors_misconfiguration_check,
            self.exposure_cloud_footprinting,
            self.advanced_dns_harvesting,
        ]
        
        for check in checks:
            try:
                logger.info(f"Running {check.__name__}...")
                check()
            except Exception as e:
                logger.error(f"Error in {check.__name__}: {str(e)}")
        
        end_time = time.time()
        self.results['scan_duration'] = f"{end_time - start_time:.2f} seconds"
        self.results['scan_timestamp'] = datetime.datetime.now().isoformat()
        
        logger.info(f"Footprinting completed in {end_time - start_time:.2f} seconds")
        return self.results
    
    def generate_report(self, output_file: Optional[str] = None) -> tuple:
        """Generate a comprehensive report with all findings"""
        if not self.results:
            logger.error("No results to report. Run checks first.")
            return None, None
        
        # Use safe filename if no output file specified
        if output_file is None:
            output_file = f"footprint_report_{self.safe_filename}.txt"
        
        report = f"""
ADVANCED WEBSITE FOOTPRINTING & SECURITY ASSESSMENT REPORT
==========================================================
Target Domain: {self.domain}
Original Input: {self.original_domain}
Scan Date: {self.results.get('scan_timestamp', 'N/A')}
Scan Duration: {self.results.get('scan_duration', 'N/A')}

EXECUTIVE SUMMARY:
{'-' * 50}
"""
        
        # Executive Summary
        summary_stats = {
            'Subdomains Discovered': len(self.results.get('subdomains', [])),
            'Email Patterns Found': len(self.results.get('email_patterns', [])),
            'Security Header Score': f"{self.results.get('security_headers', {}).get('score', 0)}/100",
            'CORS Vulnerabilities': len(self.results.get('cors_analysis', {}).get('vulnerabilities_found', [])),
            'Wildcard DNS': 'Yes' if self.results.get('wildcard_dns') else 'No',
            'Technologies Detected': len(self.results.get('deep_technologies', {}))
        }
        
        for key, value in summary_stats.items():
            report += f"{key}: {value}\n"
        
        # Security Assessment
        report += f"\nSECURITY ASSESSMENT:\n{'-' * 50}\n"
        
        # Security Headers
        security_headers = self.results.get('security_headers', {})
        report += f"Security Header Score: {security_headers.get('score', 0)}/100\n"
        if security_headers.get('missing_headers'):
            report += f"Missing Headers: {', '.join(security_headers['missing_headers'])}\n"
        if security_headers.get('vulnerabilities'):
            report += f"Vulnerabilities: {', '.join(security_headers['vulnerabilities'])}\n"
        
        # CORS Analysis
        cors_analysis = self.results.get('cors_analysis', {})
        report += f"CORS Risk Level: {cors_analysis.get('risk_level', 'Unknown')}\n"
        
        # Deep Technology Fingerprinting
        report += f"\nTECHNOLOGY STACK ANALYSIS:\n{'-' * 50}\n"
        technologies = self.results.get('deep_technologies', {})
        for category, items in technologies.items():
            if items:
                report += f"\n{category.upper()}:\n"
                for tech, details in items.items():
                    if isinstance(details, dict):
                        version = details.get('version', '')
                        report += f"  - {tech} {version}\n"
                    else:
                        report += f"  - {tech}: {details}\n"
        
        # DNS and Network Information
        report += f"\nNETWORK & DNS INFORMATION:\n{'-' * 50}\n"
        
        # Advanced DNS
        advanced_dns = self.results.get('advanced_dns', {})
        if advanced_dns.get('spf_records', {}).get('exists'):
            report += f"SPF Record: {advanced_dns['spf_records']['risk']} risk\n"
        else:
            report += "SPF Record: Not found (HIGH risk)\n"
            
        if advanced_dns.get('dmarc_records', {}).get('exists'):
            report += f"DMARC Record: {advanced_dns['dmarc_records']['risk']} risk\n"
        else:
            report += "DMARC Record: Not found (HIGH risk)\n"
        
        # Subdomains
        subdomains = self.results.get('subdomains', [])
        report += f"\nDISCOVERED SUBDOMAINS ({len(subdomains)}):\n"
        for subdomain in subdomains[:20]:  # Limit display
            report += f"- {subdomain}\n"
        if len(subdomains) > 20:
            report += f"... and {len(subdomains) - 20} more\n"
        
        # Exposure Analysis
        report += f"\nEXPOSURE ANALYSIS:\n{'-' * 50}\n"
        exposure = self.results.get('exposure_analysis', {})
        exposed_files = exposure.get('exposed_files', {})
        if exposed_files:
            report += "Exposed Files Found:\n"
            for file_path, info in exposed_files.items():
                report += f"- {file_path} ({info.get('status', 'Unknown')})\n"
        
        # Google Dorks
        dorks = exposure.get('google_dorks', [])
        report += f"\nRecommended Google Dorks ({len(dorks)}):\n"
        for dork in dorks[:5]:  # Show first 5 dorks
            report += f"- {dork['type']}: {dork['dork']}\n"
        
        # Recommendations
        report += f"\nSECURITY RECOMMENDATIONS:\n{'-' * 50}\n"
        
        recommendations = []
        
        # Security header recommendations
        if security_headers.get('missing_headers'):
            recommendations.extend([f"Implement {header} header" for header in security_headers['missing_headers']])
        
        # DNS recommendations
        if not advanced_dns.get('spf_records', {}).get('exists'):
            recommendations.append("Implement SPF record for email security")
        if not advanced_dns.get('dmarc_records', {}).get('exists'):
            recommendations.append("Implement DMARC record for email security")
        
        # CORS recommendations
        if cors_analysis.get('vulnerabilities_found'):
            recommendations.append("Fix CORS misconfigurations to prevent cross-origin attacks")
        
        for i, rec in enumerate(recommendations[:10], 1):  # Limit to 10 recommendations
            report += f"{i}. {rec}\n"
        
        print(report)
        
        # Save to file
        try:
            os.makedirs(os.path.dirname(output_file) if os.path.dirname(output_file) else '.', exist_ok=True)
            
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(report)
            logger.info(f"Report saved to: {output_file}")
            
            # Also save raw JSON data
            json_file = output_file.replace('.txt', '.json')
            with open(json_file, 'w', encoding='utf-8') as f:
                json.dump(self.results, f, indent=2, default=str)
            logger.info(f"Raw data saved to: {json_file}")
            
            return output_file, json_file
            
        except Exception as e:
            logger.error(f"Error saving report: {str(e)}")
            # Try with a simpler filename as fallback
            try:
                simple_filename = f"footprint_report_{self.safe_filename}.txt"
                with open(simple_filename, 'w', encoding='utf-8') as f:
                    f.write(report)
                logger.info(f"Report saved with fallback name: {simple_filename}")
                return simple_filename, None
            except Exception as e2:
                logger.error(f"Fallback save also failed: {str(e2)}")
                return None, None

def main():
    parser = argparse.ArgumentParser(
        description='Advanced Website Footprinting & Security Assessment Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  %(prog)s example.com
  %(prog)s example.com --wordlist subdomains.txt
  %(prog)s example.com --timeout 15 --max-retries 5
        '''
    )
    
    parser.add_argument('domain', help='Target domain to footprint (e.g., example.com)')
    parser.add_argument('--wordlist', '-w', help='Custom subdomain wordlist file')
    parser.add_argument('--timeout', '-t', type=int, default=10, help='Request timeout in seconds (default: 10)')
    parser.add_argument('--max-retries', '-r', type=int, default=3, help='Maximum retry attempts (default: 3)')
    parser.add_argument('--output', '-o', help='Output file name')
    
    args = parser.parse_args()
    
    if not args.domain:
        parser.print_help()
        sys.exit(1)
    
    print(f"""
╔════════════════════════════════════════════════════════════════╗
║               ADVANCED FOOTPRINTING TOOL                      ║
║                    Security Assessment                        ║
╚════════════════════════════════════════════════════════════════╝
    """)
    
    print(f"[*] Target: {args.domain}")
    print(f"[*] Wordlist: {args.wordlist or 'Default'}")
    print(f"[*] Timeout: {args.timeout}s")
    print("=" * 60)
    
    try:
        # Initialize footprinting tool
        footprinter = AdvancedWebsiteFootprinter(
            domain=args.domain,
            wordlist=args.wordlist,
            timeout=args.timeout,
            max_retries=args.max_retries
        )
        
        # Run all checks
        results = footprinter.run_all_checks()
        
        # Generate report
        output_filename = args.output or f"footprint_report_{footprinter.safe_filename}.txt"
        report_file, json_file = footprinter.generate_report(output_filename)
        
        if report_file:
            print(f"\n[+] Advanced footprinting completed for {args.domain}")
            print(f"[+] Report saved as: {report_file}")
            if json_file:
                print(f"[+] JSON data saved as: {json_file}")
            
            # Print summary
            print(f"\n[SUMMARY]")
            print(f"  Subdomains found: {len(results.get('subdomains', []))}")
            print(f"  Security Score: {results.get('security_headers', {}).get('score', 0)}/100")
            print(f"  Technologies detected: {len(results.get('deep_technologies', {}))}")
        else:
            print(f"\n[-] Footprinting completed but report saving failed")
            
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    # Check for required packages
    required_packages = {
        'python-whois': 'whois',
        'dnspython': 'dns.resolver',
        'requests': 'requests'
    }
    
    print("Checking for required packages...")
    missing_packages = []
    
    for package, import_name in required_packages.items():
        try:
            if package == 'python-whois':
                import whois
            elif package == 'dnspython':
                import dns.resolver
                import dns.zone
                import dns.query
            elif package == 'requests':
                import requests
            print(f"[+] {package} is installed")
        except ImportError:
            print(f"[-] {package} is not installed")
            missing_packages.append(package)
    
    if missing_packages:
        print(f"\nPlease install missing packages using:")
        for package in missing_packages:
            print(f"  pip install {package}")
        sys.exit(1)
    
    main()