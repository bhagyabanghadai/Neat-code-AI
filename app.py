import os
from datetime import datetime
import re
import logging
from typing import Dict, List, Optional, Tuple
import httpx
from flask import Flask, request, jsonify, render_template
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase
from openai import OpenAI

# Import the new AI security pattern detector
from ai_security_patterns import AISecurityPatternDetector
# Added import for security fix validator
from security_fix_validator import SecurityFixValidator
# Import the new security fix explainer
from security_fix_explainer import SecurityFixExplainer, SecurityFixExplanation

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

class Base(DeclarativeBase):
    pass

db = SQLAlchemy(model_class=Base)
app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or "a secret key"
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL")
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
}
db.init_app(app)

# Initialize LLaMA 3 model
try:
    if not os.environ.get("LLAMA_API_KEY"):
        raise ValueError("LLAMA_API_KEY environment variable is not set")

    api_key = os.environ.get("LLAMA_API_KEY")
    llama_client = OpenAI(
        api_key=api_key,
        base_url="https://integrate.api.nvidia.com/v1",
        default_headers={
            "Accept": "application/json",
            "Content-Type": "application/json"
        }
    )
    logger.info("Attempting to initialize LLaMA client...")

    # Test the connection with minimal payload
    test_completion = llama_client.chat.completions.create(
        model="meta/llama3-70b-instruct",
        messages=[
            {
                "role": "system",
                "content": "You are a helpful assistant specialized in code security analysis."
            }
        ],
        max_tokens=1,
        temperature=0.5,
        top_p=1,
        stream=False
    )
    logger.info("LLaMA API connection test successful")

except Exception as e:
    logger.error(f"Error initializing LLaMA client: {str(e)}")
    if "401" in str(e):
        logger.error("Authentication failed. Please verify your NGC API key format and permissions.")
    elif "403" in str(e):
        logger.error("Access Denied. Please verify your NGC API key has the correct permissions.")
    elif "404" in str(e):
        logger.error("API endpoint not found. Please verify the NGC API configuration.")
    llama_client = None

def detect_programming_language(code: str) -> str:
    """
    Detect the programming language of the provided code snippet using common patterns and keywords.
    """
    # Language detection patterns
    patterns = {
        'java': (r'(class|public|private|protected|interface|enum|package|import\s+java)', 
                r'(System\.out|String\[\]|public\s+static\s+void\s+main)'),
        'python': (r'(def\s+\w+|import\s+\w+|from\s+\w+\s+import|class\s+\w+:)', 
                  r'(print\(|if\s+__name__\s*==\s*[\'"]__main__[\'"]|lambda\s+)'),
        'javascript': (r'(function|const|let|var|=>|\bmodule\.exports|\brequire\()', 
                      r'(console\.log|document\.|window\.|Promise\.)'),
        'typescript': (r'(interface\s+\w+|type\s+\w+|export\s+class)', 
                      r'(:string\b|:number\b|:boolean\b|:any\b)'),
        'go': (r'(package\s+main|func\s+\w+|import\s+[\'"])', 
               r'(fmt\.|go\s+func|struct\s+\{)'),
        'rust': (r'(fn\s+\w+|let\s+mut|impl\s+\w+|use\s+\w+)', 
                r'(println!\(|Vec<|Option<|Result<)'),
        'cpp': (r'(#include\s*<|std::|cout\s*<<)', 
               r'(void\s+\w+\s*\(|int\s+main\s*\()'),
        'csharp': (r'(namespace\s+\w+|using\s+System|public\s+class)', 
                  r'(Console\.|string\[\]|void\s+Main\()'),
    }

    # Count matches for each language
    scores: Dict[str, int] = {lang: 0 for lang in patterns}

    for lang, (pattern1, pattern2) in patterns.items():
        matches1 = len(re.findall(pattern1, code, re.IGNORECASE | re.MULTILINE))
        matches2 = len(re.findall(pattern2, code, re.IGNORECASE | re.MULTILINE))
        scores[lang] = matches1 + matches2

    # Get the language with the highest score
    detected_lang = max(scores.items(), key=lambda x: x[1])

    # If no clear patterns are found, return 'unknown'
    return detected_lang[0] if detected_lang[1] > 0 else 'unknown'

# Initialize the AI pattern detector
ai_pattern_detector = AISecurityPatternDetector()

# Initialize the security fix validator
security_validator = SecurityFixValidator()

# Initialize the security fix explainer after other initializations
security_explainer = SecurityFixExplainer()

def calculate_confidence_score(vulnerabilities, severity_level, code_complexity):
    """
    Calculate confidence score based on multiple factors:
    - Number and severity of vulnerabilities
    - Pattern match confidence
    - Code complexity
    - AI model confidence
    """
    base_score = 100.0

    # Factor 1: Vulnerability severity impact
    severity_weights = {
        'Critical': -20,
        'High': -15,
        'Medium': -10,
        'Low': -5
    }
    severity_impact = severity_weights.get(severity_level, 0)

    # Factor 2: Number of vulnerabilities impact
    vuln_count = len(vulnerabilities)
    vuln_impact = min(-5 * vuln_count, -30)  # Cap at -30

    # Factor 3: Pattern match confidence (average of all vulnerabilities)
    pattern_confidence = 0.0
    if vulnerabilities:
        pattern_scores = [v.get('confidence', 0.5) for v in vulnerabilities]
        pattern_confidence = (sum(pattern_scores) / len(pattern_scores)) * 100

    # Factor 4: Code complexity (basic measure)
    complexity_factor = -5 if code_complexity > 100 else 0

    # Calculate final score
    confidence_score = base_score + severity_impact + vuln_impact + complexity_factor
    confidence_score = max(0, min(100, confidence_score))

    # Adjust based on pattern confidence
    final_score = (confidence_score + pattern_confidence) / 2

    return round(final_score, 2)

def get_code_complexity(code: str) -> int:
    """Basic code complexity measurement"""
    # Count control structures and nesting levels
    control_structures = len(re.findall(r'\b(if|for|while|switch|try|catch)\b', code))
    nesting_level = len(re.findall(r'^[\s\t]*[{}]', code, re.MULTILINE))
    return control_structures + nesting_level

def detect_code_vulnerabilities(code: str, language: str) -> Tuple[List[str], float]:
    """Enhanced vulnerability detection system with AI-powered analysis and confidence scoring"""
    try:
        # Get vulnerabilities using AI pattern detector
        vulnerabilities = ai_pattern_detector.analyze_code(code, language)

        # Calculate average confidence score
        total_confidence = sum(vuln['confidence'] for vuln in vulnerabilities)
        avg_confidence = total_confidence / len(vulnerabilities) if vulnerabilities else 0.0

        # Format vulnerabilities for output, including confidence scores
        formatted_vulnerabilities = []
        for vuln in vulnerabilities:
            severity = vuln['severity']
            description = vuln['description']
            confidence = vuln['confidence']
            formatted_vulnerabilities.append(
                f"{severity} (Confidence: {confidence:.2f}): {description}"
            )

        return formatted_vulnerabilities, avg_confidence

    except Exception as e:
        logger.error(f"Error in vulnerability detection: {str(e)}")
        return ["Error: Failed to analyze code properly"], 0.0

def get_language_specific_prompt(language: str, code: str, vulnerabilities: List[str]) -> str:
    """Generate language-specific analysis prompt"""
    base_prompt = f"""### 🚀 Secure Code Analysis Instructions

Analyze this {language.upper()} code and provide a comprehensive security fix:

{code}

Current vulnerabilities:
{chr(10).join(vulnerabilities) if vulnerabilities else "Initial scan completed."}

Required:
1. Replace ALL hardcoded credentials with environment variables
2. Implement proper error handling and logging
3. Add input validation
4. Apply language-specific security best practices
"""

    language_specific = {
        "java": """
5. Use PreparedStatement for ALL SQL queries
6. Implement proper resource management with try-with-resources
7. Use proper exception handling without printStackTrace()
""",
        "python": """
5. Use parameterized queries for database operations
6. Implement proper context managers for resource handling
7. Use secure random number generation
""",
        "javascript": """
5. Use proper input sanitization
6. Implement Content Security Policy
7. Use secure session management
"""
    }

    return base_prompt + (language_specific.get(language, ""))

def verify_security_fix(code: str, fixed_code: str, language: str) -> Tuple[bool, List[str]]:
    """Enhanced security fix verification with detailed validation"""
    try:
        validation_result = security_validator.validate_security_fix(code, fixed_code, language)

        return validation_result.is_valid, validation_result.issues
    except Exception as e:
        logger.error(f"Error in security fix verification: {str(e)}")
        return False, [f"Verification error: {str(e)}"]

def apply_security_fix(code, suggested_fix, language):
    """Enhanced security fix application system with verification"""
    try:
        if not code or not suggested_fix:
            return None, ["Invalid input: Missing code or fix"]

        # Start with the AI-suggested fix
        fixed_code = suggested_fix.strip()
        validation_errors = []

        if language.lower() == 'java':
            # Apply security improvements
            security_replacements = [
                # Convert hardcoded credentials to environment variables
                (r'String\s+(\w+)\s*=\s*["\']([^"\']+)["\'];',
                 lambda m: f'String {m.group(1)} = System.getenv("{m.group(1).upper()}");'),

                # Ensure proper resource handling with try-with-resources
                (r'Connection\s+(\w+)\s*=\s*DriverManager\.getConnection',
                 lambda m: f'try (Connection {m.group(1)} = DriverManager.getConnection'),

                # Replace insecure logging
                (r'System\.out\.println\((.*?)\);',
                 lambda m: f'logger.info({m.group(1)});'),

                # Convert Statement to PreparedStatement
                (r'Statement\s+(\w+)\s*=\s*(\w+)\.createStatement\(\)',
                 lambda m: f'PreparedStatement {m.group(1)} = {m.group(2)}.prepareStatement(query)'),

                # Fix SQL injection by replacing string concatenation with parameterized queries
                (r'[\'"](SELECT|UPDATE|DELETE|INSERT)[^"\']*[\'"]\s*\+\s*(\w+)',
                 lambda m: f'"{m.group(1)} ... WHERE ... = ?" // Parameter will be set using setString()')
            ]

            # Apply each security fix pattern
            for pattern, replacement in security_replacements:
                try:
                    fixed_code = re.sub(pattern, replacement, fixed_code)
                except Exception as regex_error:
                    logger.error(f"Regex error with pattern {pattern}: {str(regex_error)}")
                    continue

            # Add necessary imports
            required_imports = [
                'import java.sql.PreparedStatement;',
                'import java.util.logging.Logger;',
                'import java.util.logging.Level;'
            ]

            # Check existing imports
            existing_imports = set(re.findall(r'import\s+([^;]+);', fixed_code))
            for imp in required_imports:
                imp_name = imp.replace('import ', '').replace(';', '')
                if imp_name not in existing_imports:
                    fixed_code = imp + '\n' + fixed_code

            # Add logger initialization if missing
            if 'private static final Logger' not in fixed_code:
                class_match = re.search(r'class\s+(\w+)', fixed_code)
                if class_match:
                    logger_init = f'\n    private static final Logger logger = Logger.getLogger({class_match.group(1)}.class.getName());'
                    fixed_code = re.sub(r'class\s+\w+\s*\{', f'class {class_match.group(1)} {{\n{logger_init}', fixed_code)

            # Verify the security improvements
            is_secure, missing_requirements = verify_security_fix(fixed_code, language)
            if not is_secure:
                validation_errors.extend(missing_requirements)
                # Try to enhance the fix
                fixed_code = enhance_security_fix(fixed_code, validation_errors, language)
                # Verify again after enhancement
                is_secure, remaining_issues = verify_security_fix(fixed_code, language)
                if not is_secure:
                    validation_errors.extend(remaining_issues)

        return fixed_code, validation_errors

    except Exception as e:
        logger.error(f"Error applying security fix: {str(e)}")
        return None, [f"Error applying security fix: {str(e)}"]

def enhance_security_fix(code, validation_errors, language):
    """Attempt to enhance the security fix based on validation errors"""
    enhanced_code = code

    if language.lower() == 'java':
        # Add necessary imports
        if 'logger' in code and 'import java.util.logging' not in code:
            enhanced_code = 'import java.util.logging.Logger;\n' + enhanced_code

        # Add logger initialization if missing
        if 'logger' in code and 'private static final Logger' not in enhanced_code:
            class_match = re.search(r'class\s+(\w+)', enhanced_code)
            if class_match:
                logger_init = f'\n    private static final Logger logger = Logger.getLogger({class_match.group(1)}.class.getName());'
                enhanced_code = re.sub(r'class\s+\w+\s*\{', f'class {class_match.group(1)} {{\n{logger_init}', enhanced_code)

        # Ensure proper exception handling
        if 'catch' in enhanced_code and 'printStackTrace' in enhanced_code:
            enhanced_code = enhanced_code.replace('printStackTrace()', 'logger.severe(e.getMessage())')

    return enhanced_code

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/analyze', methods=['POST'])
def analyze_code():
    data = request.get_json()
    if not data or 'code' not in data:
        return jsonify({'error': 'No code provided'}), 400

    code = data['code']
    detected_language = detect_programming_language(code)
    language = data.get('language', detected_language)

    try:
        if not llama_client:
            return jsonify({'error': 'LLaMA client not initialized properly'}), 500

        # Record analysis start time
        analysis_start = datetime.utcnow()

        # Get initial vulnerabilities with confidence scores
        initial_vulnerabilities = ai_pattern_detector.analyze_code(code, language)

        # Calculate code complexity
        code_complexity = get_code_complexity(code)

        # Extract severity levels and counts
        severity_counts = {
            'Critical': sum(1 for v in initial_vulnerabilities if v['severity'] == 'Critical'),
            'High': sum(1 for v in initial_vulnerabilities if v['severity'] == 'High'),
            'Medium': sum(1 for v in initial_vulnerabilities if v['severity'] == 'Medium'),
            'Low': sum(1 for v in initial_vulnerabilities if v['severity'] == 'Low')
        }

        # Determine overall severity level
        overall_severity = 'Low'
        if severity_counts['Critical'] > 0:
            overall_severity = 'Critical'
        elif severity_counts['High'] > 0:
            overall_severity = 'High'
        elif severity_counts['Medium'] > 0:
            overall_severity = 'Medium'

        # Calculate confidence score
        confidence_score = calculate_confidence_score(
            initial_vulnerabilities,
            overall_severity,
            code_complexity
        )

        # Format vulnerabilities with confidence scores
        formatted_vulnerabilities = []
        for vuln in initial_vulnerabilities:
            formatted_vulnerabilities.append(
                f"{vuln['severity']} (Confidence: {vuln['confidence']*100:.1f}%): {vuln['description']}"
            )

        # Generate language-specific security prompt
        security_prompt = get_language_specific_prompt(language, code, formatted_vulnerabilities)

        # Get AI analysis with confidence information
        completion = llama_client.chat.completions.create(
            model="meta/llama3-70b-instruct",
            messages=[
                {
                    "role": "system",
                    "content": """You are a security expert. Analyze the code and provide a detailed response with confidence scores in this format:

SECURITY_ANALYSIS:
[List all security vulnerabilities found with confidence scores]

SEVERITY:
[Critical/High/Medium/Low]

CONFIDENCE_DETAILS:
- Pattern Match Confidence: [0-100%]
- AI Analysis Confidence: [0-100%]
- Overall Solution Confidence: [0-100%]

EXPLANATION:
[Detailed explanation of each vulnerability]

SUGGESTED_FIX:
[Complete corrected code with all security fixes applied]"""
                },
                {"role": "user", "content": security_prompt}
            ],
            temperature=0.5,
            top_p=1,
            max_tokens=2048
        )

        response = completion.choices[0].message.content
        suggested_fix = response.split('SUGGESTED_FIX:')[-1].strip() if 'SUGGESTED_FIX:' in response else ''

        # Generate detailed fix explanation
        explanation = security_explainer.generate_explanation(
            original_code=code,
            fixed_code=suggested_fix,
            vulnerability_type=initial_vulnerabilities[0]['description'] if initial_vulnerabilities else "Unknown",
            severity=overall_severity
        )

        # Format the explanation as HTML
        formatted_explanation = security_explainer.format_explanation_html(explanation) if explanation else ""

        # Create analysis record with enhanced fields
        from models import CodeAnalysis
        analysis = CodeAnalysis(
            code_snippet=code,
            language=language,
            vulnerability_found=bool(initial_vulnerabilities),
            vulnerability_type='\n'.join(formatted_vulnerabilities),
            severity_level=overall_severity,
            owasp_category="A03:2021-Injection" if "SQL Injection" in str(initial_vulnerabilities) else "A07:2021-Authentication",
            ai_explanation=response,
            suggested_fix=suggested_fix,
            fix_explanation=formatted_explanation,  # Store the formatted explanation
            analysis_started_at=analysis_start,
            analysis_completed_at=datetime.utcnow(),
            security_score=max(0, 100 - (len(initial_vulnerabilities) * 10)),
            fix_confidence_score=confidence_score,
            dynamic_analysis_result={
                'detected_language': detected_language,
                'vulnerability_count': len(initial_vulnerabilities),
                'confidence_score': confidence_score,
                'confidence_breakdown': {
                    'pattern_match_confidence': sum(v['confidence'] for v in initial_vulnerabilities) / len(initial_vulnerabilities) * 100 if initial_vulnerabilities else 100,
                    'severity_based_confidence': max(0, 100 - (severity_counts['Critical'] * 20 + severity_counts['High'] * 15 + severity_counts['Medium'] * 10 + severity_counts['Low'] * 5)),
                    'code_complexity_impact': max(0, 100 - code_complexity),
                },
                'severity_distribution': severity_counts
            }
        )

        db.session.add(analysis)
        db.session.commit()

        return jsonify(analysis.to_dict()), 200

    except Exception as e:
        logger.error(f"Error in analyze_code: {str(e)}")
        return jsonify({'error': f'An unexpected error occurred: {str(e)}'}), 500

@app.route('/api/apply_fix', methods=['POST'])
def apply_fix():
    data = request.get_json()
    if not data or 'code' not in data or 'analysis_id' not in data:
        return jsonify({'error': 'Missing required parameters'}), 400

    try:
        from models import CodeAnalysis
        analysis = CodeAnalysis.query.get(data['analysis_id'])
        if not analysis:
            return jsonify({'error': 'Analysis not found'}), 404

        # Apply the security fix
        fixed_code, validation_errors = apply_security_fix(
            data['code'],
            analysis.suggested_fix,
            analysis.language
        )

        if validation_errors and not fixed_code:
            return jsonify({
                'error': 'Failed to apply security fix',
                'validation_errors': validation_errors
            }), 400

        # Enhanced validation of the security fix
        is_valid, validation_issues = verify_security_fix(data['code'], fixed_code, analysis.language)

        # Get validation details
        validation_result = security_validator.validate_security_fix(
            data['code'], 
            fixed_code, 
            analysis.language
        )

        # Update the analysis record with validation results
        analysis.fix_verified = is_valid
        analysis.fix_confidence_score = validation_result.confidence_score * 100
        db.session.commit()

        return jsonify({
            'fixed_code': fixed_code,
            'validation_status': {
                'is_valid': is_valid,
                'issues': validation_issues,
                'recommendations': validation_result.recommendations,
                'confidence_score': validation_result.confidence_score * 100,
                'validation_details': validation_result.validation_details
            }
        }), 200

    except Exception as e:
        logger.error(f"Error in apply_fix: {str(e)}")
        return jsonify({'error': f'An unexpected error occurred: {str(e)}'}), 500

with app.app_context():
    import models  # noqa: F401
    db.create_all()