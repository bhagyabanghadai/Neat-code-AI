import re
from typing import List, Dict, Optional
import logging
from dataclasses import dataclass

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

@dataclass
class SecurityFixExplanation:
    original_code: str
    fixed_code: str
    vulnerability_type: str
    severity: str
    explanation: str
    best_practices: List[str]
    security_impact: str
    owasp_category: str
    fix_steps: List[str]
    code_snippets: Dict[str, str]
    additional_resources: List[str]

class SecurityFixExplainer:
    def __init__(self):
        self.vulnerability_categories = {
            "sql_injection": {
                "name": "SQL Injection",
                "owasp": "A03:2021-Injection",
                "resources": [
                    "https://owasp.org/www-project-top-ten/2021/A03_2021-Injection",
                    "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"
                ]
            },
            "xss": {
                "name": "Cross-Site Scripting (XSS)",
                "owasp": "A03:2021-Injection",
                "resources": [
                    "https://owasp.org/www-project-top-ten/2021/A03_2021-Injection",
                    "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"
                ]
            },
            "hardcoded_credentials": {
                "name": "Hardcoded Credentials",
                "owasp": "A07:2021-Identification and Authentication Failures",
                "resources": [
                    "https://owasp.org/www-project-top-ten/2021/A07_2021-Identification_and_Authentication_Failures"
                ]
            }
        }

    def extract_relevant_code_snippets(self, code: str, vulnerability_type: str) -> Dict[str, str]:
        """Extract relevant code snippets based on vulnerability type"""
        snippets = {}

        patterns = {
            "sql_injection": r"(?:SELECT|INSERT|UPDATE|DELETE).*?;",
            "hardcoded_credentials": r"(?:password|secret|key)\s*=\s*[\"'][^\"']+[\"']",
            "xss": r"innerHTML\s*=|document\.write\(",
            "file_operations": r"new\s+File\([^)]*\)",
            "error_handling": r"try\s*{[^}]*}\s*catch",
            "logging": r"(?:System\.out\.println|console\.log|print)\([^)]*\)"
        }

        try:
            for vuln_type, pattern in patterns.items():
                matches = re.finditer(pattern, code, re.MULTILINE | re.IGNORECASE)
                for i, match in enumerate(matches, 1):
                    context_start = max(0, match.start() - 50)
                    context_end = min(len(code), match.end() + 50)
                    snippets[f"{vuln_type}_{i}"] = code[context_start:context_end].strip()

        except Exception as e:
            logger.error(f"Error extracting code snippets: {str(e)}")
            return {}

        return snippets

    def generate_explanation(self, original_code: str, fixed_code: str, 
                           vulnerability_type: str, severity: str) -> SecurityFixExplanation:
        """Generate detailed explanation for a security fix"""
        try:
            vuln_info = self.vulnerability_categories.get(
                vulnerability_type.lower(),
                {
                    "name": vulnerability_type,
                    "owasp": "A00:2021-Unknown",
                    "resources": []
                }
            )

            # Extract relevant code snippets
            code_snippets = self.extract_relevant_code_snippets(original_code, vulnerability_type)

            # Generate fix steps based on the changes
            fix_steps = self._analyze_changes(original_code, fixed_code)

            # Generate security impact explanation
            security_impact = self._analyze_security_impact(vulnerability_type, severity)

            # Compile best practices
            best_practices = self._get_best_practices(vulnerability_type)

            # Create the explanation
            explanation = f"""
Security Fix Analysis for {vuln_info['name']}

VULNERABILITY DETAILS:
- Type: {vuln_info['name']}
- Severity: {severity}
- OWASP Category: {vuln_info['owasp']}

SECURITY IMPACT:
{security_impact}

EXPLANATION OF THE FIX:
{chr(10).join(f"- {step}" for step in fix_steps)}

BEST PRACTICES:
{chr(10).join(f"- {practice}" for practice in best_practices)}

For more information, refer to:
{chr(10).join(f"- {resource}" for resource in vuln_info['resources'])}
"""

            return SecurityFixExplanation(
                original_code=original_code,
                fixed_code=fixed_code,
                vulnerability_type=vuln_info['name'],
                severity=severity,
                explanation=explanation,
                best_practices=best_practices,
                security_impact=security_impact,
                owasp_category=vuln_info['owasp'],
                fix_steps=fix_steps,
                code_snippets=code_snippets,
                additional_resources=vuln_info['resources']
            )

        except Exception as e:
            logger.error(f"Error generating explanation: {str(e)}")
            return None

    def _analyze_changes(self, original_code: str, fixed_code: str) -> List[str]:
        """Analyze the changes made to fix the vulnerability"""
        fix_steps = []

        try:
            # Compare the original and fixed code to identify changes
            if "PreparedStatement" in fixed_code and "Statement" in original_code:
                fix_steps.append("Replaced vulnerable Statement with PreparedStatement to prevent SQL injection")

            if "System.getenv" in fixed_code and re.search(r"[\"'][^\"']+[\"']", original_code):
                fix_steps.append("Replaced hardcoded credentials with environment variables")

            if "try" in fixed_code and "try" not in original_code:
                fix_steps.append("Added proper exception handling with try-catch blocks")

            if "LOGGER" in fixed_code and "printStackTrace" in original_code:
                fix_steps.append("Replaced printStackTrace() with proper logging")

            if not fix_steps:
                fix_steps.append("Applied security fixes based on best practices")

        except Exception as e:
            logger.error(f"Error analyzing changes: {str(e)}")
            fix_steps.append("Applied security fixes (error analyzing specific changes)")

        return fix_steps

    def _analyze_security_impact(self, vulnerability_type: str, severity: str) -> str:
        """Generate detailed security impact analysis"""
        impact_templates = {
            "sql_injection": """
SQL Injection vulnerabilities can allow attackers to:
1. Access unauthorized data from the database
2. Modify or delete database contents
3. Execute administrative operations
4. Potentially gain system access

This vulnerability is particularly critical as it can lead to complete database compromise.""",

            "hardcoded_credentials": """
Hardcoded credentials in source code can lead to:
1. Unauthorized access if code is exposed
2. Difficulty in credential rotation
3. Security breaches in version control
4. Compliance violations

This represents a significant security risk, especially in distributed or open-source code.""",

            "xss": """
Cross-Site Scripting (XSS) vulnerabilities enable attackers to:
1. Inject malicious scripts into web pages
2. Steal user sessions and credentials
3. Deface websites
4. Redirect users to malicious sites

This can lead to significant user account compromises and data theft."""
        }

        return impact_templates.get(
            vulnerability_type.lower(),
            f"This {severity.lower()} severity vulnerability could potentially compromise system security and should be addressed according to security best practices."
        )

    def _get_best_practices(self, vulnerability_type: str) -> List[str]:
        """Get relevant best practices for the vulnerability type"""
        best_practices_dict = {
            "sql_injection": [
                "Always use PreparedStatement or parameterized queries",
                "Validate and sanitize all user inputs",
                "Use an ORM when possible",
                "Implement proper error handling without exposing SQL errors",
                "Apply the principle of least privilege for database users"
            ],
            "hardcoded_credentials": [
                "Store sensitive data in environment variables",
                "Use secure credential management systems",
                "Implement proper secret rotation mechanisms",
                "Never commit credentials to version control",
                "Use encryption for storing sensitive data"
            ],
            "xss": [
                "Validate and sanitize all user inputs",
                "Use Content Security Policy (CSP) headers",
                "Implement proper output encoding",
                "Use modern framework's built-in XSS protections",
                "Apply the principle of least privilege"
            ]
        }

        return best_practices_dict.get(vulnerability_type.lower(), [
            "Follow the principle of least privilege",
            "Implement proper input validation",
            "Use secure coding practices",
            "Maintain updated security dependencies",
            "Implement proper logging and monitoring"
        ])

    def format_explanation_html(self, explanation: SecurityFixExplanation) -> str:
        """Format the security fix explanation as HTML"""
        return f"""
<div class="security-fix-explanation">
    <h2>Security Fix Analysis: {explanation.vulnerability_type}</h2>
    
    <div class="severity-badge severity-{explanation.severity.lower()}">
        {explanation.severity}
    </div>
    
    <div class="owasp-category">
        OWASP Category: {explanation.owasp_category}
    </div>
    
    <div class="security-impact">
        <h3>Security Impact</h3>
        <p>{explanation.security_impact}</p>
    </div>
    
    <div class="fix-steps">
        <h3>Fix Implementation Steps</h3>
        <ol>
            {"".join(f"<li>{step}</li>" for step in explanation.fix_steps)}
        </ol>
    </div>
    
    <div class="code-comparison">
        <h3>Code Changes</h3>
        <div class="code-block original">
            <h4>Original Code</h4>
            <pre><code>{explanation.original_code}</code></pre>
        </div>
        <div class="code-block fixed">
            <h4>Fixed Code</h4>
            <pre><code>{explanation.fixed_code}</code></pre>
        </div>
    </div>
    
    <div class="best-practices">
        <h3>Security Best Practices</h3>
        <ul>
            {"".join(f"<li>{practice}</li>" for practice in explanation.best_practices)}
        </ul>
    </div>
    
    <div class="additional-resources">
        <h3>Additional Resources</h3>
        <ul>
            {"".join(f"<li><a href='{resource}' target='_blank'>{resource}</a></li>" for resource in explanation.additional_resources)}
        </ul>
    </div>
</div>
"""