from datetime import datetime
from app import db

class CodeAnalysis(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    code_snippet = db.Column(db.Text, nullable=False)
    language = db.Column(db.String(50), nullable=False)
    vulnerability_found = db.Column(db.Boolean, default=False)
    vulnerability_type = db.Column(db.Text)
    severity_level = db.Column(db.String(20))  # Critical/High/Medium/Low
    owasp_category = db.Column(db.Text)
    ai_explanation = db.Column(db.Text)
    suggested_fix = db.Column(db.Text)
    fix_explanation = db.Column(db.Text)  # New field for detailed fix explanation
    additional_recommendations = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # New fields for enhanced AI analysis
    ai_model_version = db.Column(db.String(50), default="llama-3.1-sonar-small-128k")
    analysis_started_at = db.Column(db.DateTime)
    analysis_completed_at = db.Column(db.DateTime)
    fix_verified = db.Column(db.Boolean, default=False)
    security_score = db.Column(db.Float)  # 0-100 score
    fix_confidence_score = db.Column(db.Float)  # 0-100 score
    dynamic_analysis_result = db.Column(db.JSON)  # Store detailed analysis data

    def to_dict(self):
        return {
            'id': self.id,
            'code_snippet': self.code_snippet,
            'language': self.language,
            'vulnerability_found': self.vulnerability_found,
            'vulnerability_type': self.vulnerability_type,
            'severity_level': self.severity_level,
            'owasp_category': self.owasp_category,
            'ai_explanation': self.ai_explanation,
            'suggested_fix': self.suggested_fix,
            'fix_explanation': self.fix_explanation, #Added this line
            'additional_recommendations': self.additional_recommendations,
            'created_at': self.created_at.isoformat(),
            'ai_model_version': self.ai_model_version,
            'analysis_started_at': self.analysis_started_at.isoformat() if self.analysis_started_at else None,
            'analysis_completed_at': self.analysis_completed_at.isoformat() if self.analysis_completed_at else None,
            'fix_verified': self.fix_verified,
            'security_score': self.security_score,
            'fix_confidence_score': self.fix_confidence_score,
            'dynamic_analysis_result': self.dynamic_analysis_result
        }