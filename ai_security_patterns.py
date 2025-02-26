import re
from typing import List, Dict, Tuple, Optional
from datetime import datetime
import logging
from openai import OpenAI
import os

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

class AISecurityPatternDetector:
    def __init__(self):
        self.llama_client = OpenAI(
            api_key=os.environ.get("LLAMA_API_KEY"),
            base_url="https://integrate.api.nvidia.com/v1",
            default_headers={
                "Accept": "application/json",
                "Content-Type": "application/json"
            }
        )

        # Initialize base patterns with confidence scores
        self.base_patterns: Dict[str, List[Tuple[str, str, float]]] = {
            "java": self._get_java_patterns(),
            "python": self._get_python_patterns(),
            "javascript": self._get_javascript_patterns()
        }

    def _get_java_patterns(self) -> List[Tuple[str, str, float]]:
        return [
            # Critical Vulnerabilities (Higher confidence)
            (r"(?:SELECT|INSERT|UPDATE|DELETE).*?[\+].*?(?:\+|;)",
             "SQL Injection vulnerability through string concatenation",
             0.95),  # High confidence for SQL injection
            (r"(?:createStatement\(\)).*?execute(?:Query|Update)\([^)]*\+[^)]*\)",
             "Dynamic SQL execution with potential injection risks",
             0.95),
            (r"new\s+File\([^)]*\)(?!.*?try)",
             "Unhandled file operations",
             0.90),
            (r"SecretKeySpec\([^)]*\"[^\"]+\"[^)]*\)",
             "Hardcoded encryption key",
             0.98),  # Very high confidence for hardcoded keys

            # Authentication & Authorization (Medium confidence)
            (r"\.equals\([^)]*password[^)]*\)",
             "Insecure password comparison using equals()",
             0.85),
            (r"\.getSession\(\)\.setAttribute\([^)]*(?:token|auth)[^)]*\)",
             "Session fixation vulnerability",
             0.80),

            # Communication Security (Medium confidence)
            (r"http://",
             "Insecure HTTP protocol usage",
             0.75),
            (r"SSLContext\.getInstance\(\"SSL\"\)",
             "Deprecated SSL protocol usage",
             0.85),

            # Information Exposure (Lower confidence due to context dependency)
            (r"e\.printStackTrace\(\)",
             "Sensitive information exposure through stack trace",
             0.70),
            (r"System\.out\.println\([^)]*(?:password|secret|key)[^)]*\)",
             "Logging sensitive information",
             0.65)
        ]

    def _get_python_patterns(self) -> List[Tuple[str, str, float]]:
        return [
            # Critical Vulnerabilities (Higher confidence)
            (r"eval\([^)]*\)",
             "Dangerous eval() usage",
             0.95),
            (r"exec\([^)]*\)",
             "Dangerous exec() usage",
             0.95),
            (r"%.*?%.*?%",
             "SQL Injection through string formatting",
             0.90),

            # Authentication & Authorization (Medium confidence)
            (r"md5\([^)]*password[^)]*\)",
             "Weak password hashing using MD5",
             0.85),
            (r"\.decode\('base64'\)",
             "Insecure base64 decoding",
             0.75),

            # Information Exposure (Lower confidence)
            (r"print\([^)]*(?:password|secret|key)[^)]*\)",
             "Logging sensitive information",
             0.65),
            (r"logging\.(?:info|debug|error)\([^)]*(?:password|secret|key)[^)]*\)",
             "Logging sensitive information in logs",
             0.70),

            # Input Validation (Higher confidence)
            (r"pickle\.loads?\([^)]*\)",
             "Unsafe deserialization using pickle",
             0.90),
            (r"yaml\.load\([^)]*\)",
             "Unsafe YAML loading",
             0.85)
        ]

    def _get_javascript_patterns(self) -> List[Tuple[str, str, float]]:
        return [
            # Critical Vulnerabilities (Higher confidence)
            (r"eval\([^)]*\)",
             "Dangerous eval() usage",
             0.95),
            (r"document\.write\([^)]*\)",
             "Unsafe document.write() usage",
             0.85),
            (r"innerHTML.*?=.*?\+",
             "XSS vulnerability through innerHTML",
             0.90),

            # Storage Security (Medium confidence)
            (r"localStorage\.setItem\([^)]*(?:token|password|secret)[^)]*\)",
             "Storing sensitive data in localStorage",
             0.80),
            (r"sessionStorage\.setItem\([^)]*(?:token|password|secret)[^)]*\)",
             "Storing sensitive data in sessionStorage",
             0.75),

            # Information Exposure (Lower confidence)
            (r"console\.log\([^)]*(?:password|secret|key)[^)]*\)",
             "Logging sensitive information",
             0.65),

            # Input Validation (Higher confidence)
            (r"new\s+Function\([^)]*\)",
             "Dangerous dynamic function creation",
             0.90),
            (r"setTimeout\([^)]*string[^)]*\)",
             "Potential code injection in setTimeout",
             0.85)
        ]

    def analyze_code(self, code: str, language: str) -> List[Dict[str, str]]:
        """Analyze code using both pattern matching and AI-driven analysis with confidence scores"""
        vulnerabilities = []
        try:
            # Pattern-based detection with confidence scores
            patterns = self.base_patterns.get(language.lower(), [])
            for pattern, description, confidence in patterns:
                if re.search(pattern, code, re.IGNORECASE | re.MULTILINE):
                    vulnerabilities.append({
                        "type": "pattern",
                        "severity": "Critical" if confidence > 0.9 else ("High" if confidence > 0.8 else "Medium"),
                        "description": description,
                        "confidence": confidence
                    })

            # AI-driven analysis
            try:
                ai_response = self.llama_client.chat.completions.create(
                    model="meta/llama3-70b-instruct",
                    messages=[
                        {
                            "role": "system",
                            "content": "You are a security expert. Analyze the code for security vulnerabilities. "
                                     "For each finding, provide: 1) Description 2) Severity 3) Confidence score (0-1) "
                                     "Focus on actual security risks, not style issues."
                        },
                        {
                            "role": "user",
                            "content": f"Analyze this {language} code for security issues:\n\n{code}"
                        }
                    ],
                    temperature=0.2,
                    max_tokens=1000
                )

                ai_findings = ai_response.choices[0].message.content
                if ai_findings:
                    vulnerabilities.extend(self._parse_ai_findings(ai_findings))

            except Exception as e:
                logger.error(f"Error in AI analysis: {str(e)}")

            return self._deduplicate_vulnerabilities(vulnerabilities)

        except Exception as e:
            logger.error(f"Error in pattern analysis: {str(e)}")
            return []

    def _parse_ai_findings(self, findings: str) -> List[Dict[str, str]]:
        """Parse AI findings into structured vulnerability data with confidence scores"""
        ai_vulnerabilities = []
        issues = findings.split('\n')

        for issue in issues:
            if not issue.strip():
                continue

            # Determine severity and confidence
            severity = "High"
            confidence = 0.8  # Default confidence

            if any(keyword in issue.lower() for keyword in ["critical", "severe", "dangerous"]):
                severity = "Critical"
                confidence = 0.9
            elif any(keyword in issue.lower() for keyword in ["medium", "moderate"]):
                severity = "Medium"
                confidence = 0.7
            elif any(keyword in issue.lower() for keyword in ["low", "minor"]):
                severity = "Low"
                confidence = 0.6

            # Adjust confidence based on certainty indicators
            if any(word in issue.lower() for word in ["definitely", "certainly", "clearly"]):
                confidence = min(confidence + 0.1, 1.0)
            elif any(word in issue.lower() for word in ["possibly", "might", "maybe"]):
                confidence = max(confidence - 0.1, 0.0)

            ai_vulnerabilities.append({
                "type": "ai",
                "severity": severity,
                "description": issue.strip(),
                "confidence": confidence
            })

        return ai_vulnerabilities

    def _deduplicate_vulnerabilities(self, vulnerabilities: List[Dict[str, str]]) -> List[Dict[str, str]]:
        """Remove duplicate vulnerabilities while preserving the highest confidence score"""
        unique_vulnerabilities = {}

        for vuln in vulnerabilities:
            simple_desc = re.sub(r'\W+', '', vuln['description'].lower())

            current_confidence = float(vuln['confidence'])
            if simple_desc not in unique_vulnerabilities or \
               current_confidence > float(unique_vulnerabilities[simple_desc]['confidence']):
                unique_vulnerabilities[simple_desc] = vuln

        return list(unique_vulnerabilities.values())

    def learn_new_patterns(self, code: str, vulnerabilities: List[Dict[str, str]], language: str):
        """Learn new vulnerability patterns from high-confidence findings"""
        for vuln in vulnerabilities:
            if vuln["type"] == "ai" and vuln["confidence"] > 0.9:
                # Extract pattern from the code based on high-confidence AI finding
                relevant_lines = self._extract_relevant_lines(code, vuln["description"])
                if relevant_lines:
                    pattern = self._generate_pattern_from_code(relevant_lines)
                    if pattern:
                        self.base_patterns[language].append(
                            (pattern, vuln["description"], vuln["confidence"])
                        )

    def _extract_relevant_lines(self, code: str, description: str) -> Optional[str]:
        """Extract code lines relevant to a vulnerability description"""
        # Implementation would depend on specific requirements
        return None

    def _generate_pattern_from_code(self, code_lines: str) -> Optional[str]:
        """Generate a regex pattern from code lines"""
        # Implementation would depend on specific requirements
        return None