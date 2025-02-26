import re
import logging
from typing import List, Tuple, Dict, Optional
from dataclasses import dataclass

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

@dataclass
class ValidationResult:
    is_valid: bool
    issues: List[str]
    recommendations: List[str]
    confidence_score: float
    validation_details: Dict[str, bool]

class SecurityFixValidator:
    def __init__(self):
        self.validation_patterns = {
            "java": self._get_java_validation_patterns(),
            "python": self._get_python_validation_patterns(),
            "javascript": self._get_javascript_validation_patterns()
        }

    def _get_java_validation_patterns(self) -> Dict[str, Tuple[str, str, float]]:
        return {
            "prepared_statement": (
                r"PreparedStatement.*?=.*?prepareStatement\([^)]*\)",
                "Use of PreparedStatement for SQL queries",
                0.9
            ),
            "environment_variables": (
                r"System\.getenv\([\"'][\w_]+[\"']\)",
                "Use of environment variables for configuration",
                0.8
            ),
            "secure_logging": (
                r"(?:private\s+static\s+final\s+Logger|LoggerFactory\.getLogger)\s*\([^)]+\)",
                "Proper logging implementation",
                0.7
            ),
            "try_with_resources": (
                r"try\s*\([^)]+(?:Connection|Statement|ResultSet|FileReader)[^)]*\)",
                "Resource management with try-with-resources",
                0.85
            ),
            "input_validation": (
                r"(?:Pattern\.compile|\.matches|\.replaceAll)\([^)]+\)",
                "Input validation implementation",
                0.75
            ),
            "secure_exception_handling": (
                r"catch\s*\([^)]+\)\s*\{(?![^}]*printStackTrace)",
                "Proper exception handling without printStackTrace",
                0.8
            )
        }

    def _get_python_validation_patterns(self) -> Dict[str, Tuple[str, str, float]]:
        return {
            "parameterized_query": (
                r"cursor\.execute\([^,]+,[^)]+\)",
                "Use of parameterized queries",
                0.9
            ),
            "environment_variables": (
                r"os\.(?:environ(?:\.get)?|getenv)\([\"'][\w_]+[\"']\)",
                "Use of environment variables",
                0.8
            ),
            "secure_logging": (
                r"logging\.(?:getLogger|basicConfig)",
                "Proper logging configuration",
                0.7
            ),
            "context_manager": (
                r"with\s+(?:open|closing|contextlib\.closing)",
                "Resource management with context managers",
                0.85
            ),
            "input_validation": (
                r"(?:re\.match|re\.search|\.strip|\.isalnum)\([^)]+\)",
                "Input validation implementation",
                0.75
            )
        }

    def _get_javascript_validation_patterns(self) -> Dict[str, Tuple[str, str, float]]:
        return {
            "parameterized_query": (
                r"(?:prepare|format)\([^,]+,[^)]+\)",
                "Use of parameterized queries",
                0.9
            ),
            "environment_variables": (
                r"process\.env\.[A-Z_]+",
                "Use of environment variables",
                0.8
            ),
            "secure_headers": (
                r"helmet\([^)]*\)",
                "Security headers implementation",
                0.85
            ),
            "input_sanitization": (
                r"(?:escape|sanitize|DOMPurify\.sanitize)\([^)]+\)",
                "Input sanitization implementation",
                0.8
            ),
            "content_security": (
                r"Content-Security-Policy",
                "Content Security Policy implementation",
                0.9
            )
        }

    def validate_security_fix(self, original_code: str, fixed_code: str, language: str) -> ValidationResult:
        """
        Validate that a security fix has been properly implemented
        """
        try:
            validation_details = {}
            issues = []
            recommendations = []
            total_confidence = 0.0
            patterns_checked = 0

            # Get language-specific validation patterns
            patterns = self.validation_patterns.get(language.lower(), {})
            
            # Check each security pattern
            for check_name, (pattern, description, confidence) in patterns.items():
                is_valid = bool(re.search(pattern, fixed_code, re.IGNORECASE | re.MULTILINE))
                validation_details[check_name] = is_valid
                
                if not is_valid:
                    issues.append(f"Missing {description}")
                    recommendations.append(f"Implement {description} to improve security")
                else:
                    total_confidence += confidence
                patterns_checked += 1

            # Additional checks for specific vulnerabilities
            if language.lower() == "java":
                self._validate_java_specific_fixes(fixed_code, issues, recommendations, validation_details)
            elif language.lower() == "python":
                self._validate_python_specific_fixes(fixed_code, issues, recommendations, validation_details)
            elif language.lower() == "javascript":
                self._validate_javascript_specific_fixes(fixed_code, issues, recommendations, validation_details)

            # Calculate overall confidence score
            confidence_score = (total_confidence / patterns_checked) if patterns_checked > 0 else 0.0
            
            # Validate that the fix didn't introduce new issues
            regression_issues = self._check_for_regressions(original_code, fixed_code, language)
            issues.extend(regression_issues)

            return ValidationResult(
                is_valid=len(issues) == 0,
                issues=issues,
                recommendations=recommendations,
                confidence_score=confidence_score,
                validation_details=validation_details
            )

        except Exception as e:
            logger.error(f"Error validating security fix: {str(e)}")
            return ValidationResult(
                is_valid=False,
                issues=[f"Validation error: {str(e)}"],
                recommendations=["Please review the code manually"],
                confidence_score=0.0,
                validation_details={}
            )

    def _validate_java_specific_fixes(self, code: str, issues: List[str], 
                                    recommendations: List[str], 
                                    validation_details: Dict[str, bool]):
        """Validate Java-specific security fixes"""
        if "printStackTrace" in code:
            issues.append("Insecure error handling: printStackTrace() detected")
            recommendations.append("Replace printStackTrace() with proper logging")
            validation_details["no_print_stack_trace"] = False

        if "createStatement()" in code and "prepareStatement(" not in code:
            issues.append("Potential SQL Injection: Using createStatement instead of prepareStatement")
            recommendations.append("Use PreparedStatement for all SQL queries")
            validation_details["uses_prepared_statement"] = False

    def _validate_python_specific_fixes(self, code: str, issues: List[str], 
                                      recommendations: List[str], 
                                      validation_details: Dict[str, bool]):
        """Validate Python-specific security fixes"""
        if "eval(" in code:
            issues.append("Dangerous eval() usage detected")
            recommendations.append("Remove eval() usage and implement safe alternatives")
            validation_details["no_eval"] = False

        if "%s" in code and "execute(" in code:
            issues.append("Potential SQL Injection: String formatting in SQL query")
            recommendations.append("Use parameterized queries with execute()")
            validation_details["uses_parameterized_queries"] = False

    def _validate_javascript_specific_fixes(self, code: str, issues: List[str], 
                                          recommendations: List[str], 
                                          validation_details: Dict[str, bool]):
        """Validate JavaScript-specific security fixes"""
        if "innerHTML" in code:
            issues.append("Potential XSS: innerHTML usage detected")
            recommendations.append("Use textContent or sanitize HTML content")
            validation_details["safe_dom_manipulation"] = False

        if "localStorage" in code and ("password" in code.lower() or "token" in code.lower()):
            issues.append("Sensitive data in localStorage")
            recommendations.append("Avoid storing sensitive data in localStorage")
            validation_details["secure_storage"] = False

    def _check_for_regressions(self, original_code: str, fixed_code: str, language: str) -> List[str]:
        """Check if the fix introduced any new security issues"""
        regression_issues = []
        
        # Check for removed security measures
        security_patterns = {
            "authentication": r"authenticate|login|authorize",
            "encryption": r"encrypt|decrypt|cipher",
            "validation": r"validate|sanitize|escape"
        }

        for security_type, pattern in security_patterns.items():
            original_matches = len(re.findall(pattern, original_code, re.IGNORECASE))
            fixed_matches = len(re.findall(pattern, fixed_code, re.IGNORECASE))
            
            if original_matches > fixed_matches:
                regression_issues.append(
                    f"Potential security regression: {security_type} checks may have been removed"
                )

        return regression_issues
