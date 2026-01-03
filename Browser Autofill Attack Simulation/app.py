"""
Browser Autofill Attack Simulation - Educational Tool
Project 5 - Cybersecurity Python Roadmap
Author: bnahmedsoumaya00
Date: January 2, 2026

╔═══════════════════════════════════════════════════════════════╗
║                  ⚠️  EDUCATIONAL PURPOSE ONLY ⚠️               ║
║                                                               ║
║  This tool demonstrates browser autofill security risks       ║
║  for TRAINING and AWARENESS purposes ONLY.                    ║
║                                                               ║
║  ❌ Never use for actual phishing                             ║
║  ❌ Never deploy publicly                                     ║
║  ❌ Only run locally for learning                             ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
"""

from flask import Flask, render_template, request, redirect, url_for, session, flash
import json
import os
from datetime import datetime
from functools import wraps

# Initialize Flask app
app = Flask(
    __name__,
    template_folder=os.path.abspath(
        "c:/Users/souma/Desktop/python_workspace/cybersecurity-projects/Browser Autofill Attack Simulation/templates"
    )
)
app.secret_key = 'educational_demo_key_change_in_production'  # Change for production

# Configuration
CAPTURED_DATA_FILE = 'captured_credentials.json'
TRAINING_MODE = True  # Always on for educational purposes


# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def load_captured_data():
    """Load captured credentials from file"""
    if os.path.exists(CAPTURED_DATA_FILE):
        with open(CAPTURED_DATA_FILE, 'r') as f:
            return json.load(f)
    return []


def save_captured_data(data):
    """Save captured credentials to file"""
    captured = load_captured_data()
    captured.append({
        'timestamp': datetime.now().isoformat(),
        'data': data,
        'user_agent': request.headers.get('User-Agent', 'Unknown'),
        'ip': request.remote_addr
    })
    
    with open(CAPTURED_DATA_FILE, 'w') as f:
        json.dump(captured, f, indent=4)


def educational_warning(f):
    """Decorator to show educational warnings"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('acknowledged_educational'):
            return redirect(url_for('educational_warning_page'))
        return f(*args, **kwargs)
    return decorated_function


# ============================================================================
# ROUTES - MAIN PAGES
# ============================================================================

@app.route('/')
def index():
    """Homepage - Educational dashboard"""
    return render_template('index.html')


@app.route('/warning')
def educational_warning_page():
    """Educational warning page"""
    return render_template('warning.html')


@app.route('/acknowledge-educational', methods=['POST'])
def acknowledge_educational():
    """Acknowledge educational use"""
    session['acknowledged_educational'] = True
    return redirect(url_for('index'))


@app.route('/dashboard')
@educational_warning
def dashboard():
    """Admin dashboard to view captured data"""
    captured = load_captured_data()
    return render_template('dashboard.html', captured=captured, count=len(captured))


@app.route('/training')
@educational_warning
def training():
    """Security awareness training page"""
    return render_template('training.html')


@app.route('/demo-selector')
@educational_warning
def demo_selector():
    """Select which demo to try"""
    return render_template('demo_selector.html')


# ============================================================================
# ROUTES - FAKE LOGIN PAGES (DEMOS)
# ============================================================================

@app.route('/demo/google')
@educational_warning
def demo_google():
    """Fake Google login page"""
    return render_template('demos/google_login.html')


@app.route('/demo/facebook')
@educational_warning
def demo_facebook():
    """Fake Facebook login page"""
    return render_template('demos/facebook_login.html')


@app.route('/demo/linkedin')
@educational_warning
def demo_linkedin():
    """Fake LinkedIn login page"""
    return render_template('demos/linkedin_login.html')


@app.route('/demo/github')
@educational_warning
def demo_github():
    """Fake GitHub login page"""
    return render_template('demos/github_login.html')


@app.route('/demo/banking')
@educational_warning
def demo_banking():
    """Fake banking login page"""
    return render_template('demos/banking_login.html')


# ============================================================================
# ROUTES - FORM SUBMISSIONS
# ============================================================================

@app.route('/capture', methods=['POST'])
@educational_warning
def capture_credentials():
    """Capture submitted credentials (educational demo)"""
    data = {
        'platform': request.form.get('platform', 'Unknown'),
        'email': request.form.get('email', ''),
        'username': request.form.get('username', ''),
        'password': '***HIDDEN***',  # Never log actual passwords even in demo
        'password_length': len(request.form.get('password', '')),
        'other_fields': {k: v for k, v in request.form.items() 
                        if k not in ['email', 'username', 'password', 'platform']}
    }
    
    # Save to file
    save_captured_data(data)
    
    # Show educational message
    flash('⚠️ EDUCATIONAL DEMO: Your credentials were just captured!', 'warning')
    flash(f'Platform: {data["platform"]}', 'info')
    flash(f'Email/Username: {data.get("email") or data.get("username")}', 'info')
    flash(f'Password Length: {data["password_length"]} characters', 'info')
    flash('This demonstrates how autofill can be exploited!', 'danger')
    
    # Redirect to educational page
    return redirect(url_for('capture_success'))


@app.route('/capture-success')
@educational_warning
def capture_success():
    """Show educational message after capture"""
    return render_template('capture_success.html')


# ============================================================================
# ROUTES - PROTECTION GUIDES
# ============================================================================

@app.route('/protection')
@educational_warning
def protection():
    """Protection methods guide"""
    return render_template('protection.html')


@app.route('/detection')
@educational_warning
def detection():
    """Detection methods guide"""
    return render_template('detection.html')


# ============================================================================
# ROUTES - API ENDPOINTS
# ============================================================================

@app.route('/api/stats')
@educational_warning
def api_stats():
    """Get statistics"""
    captured = load_captured_data()
    return {
        'total_captures': len(captured),
        'platforms': {}
    }


@app.route('/api/clear-data', methods=['POST'])
@educational_warning
def api_clear_data():
    """Clear captured data"""
    if os.path.exists(CAPTURED_DATA_FILE):
        os.remove(CAPTURED_DATA_FILE)
    flash('All captured data cleared!', 'success')
    return redirect(url_for('dashboard'))


# ============================================================================
# ERROR HANDLERS
# ============================================================================

@app.errorhandler(404)
def not_found(e):
    """404 error handler"""
    return render_template('404.html'), 404


@app.errorhandler(500)
def internal_error(e):
    """500 error handler"""
    return render_template('500.html'), 500


# ============================================================================
# MAIN EXECUTION
# ============================================================================

if __name__ == '__main__':
    # Create templates directory if it doesn't exist
    os.makedirs('templates', exist_ok=True)
    os.makedirs('templates/demos', exist_ok=True)
    os.makedirs('static/css', exist_ok=True)
    os.makedirs('static/js', exist_ok=True)
    os.makedirs('static/img', exist_ok=True)
    
    print("""
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║     Browser Autofill Attack Simulation - Educational Tool     ║
║                                                               ║
║  🎓 FOR EDUCATIONAL USE ONLY                                  ║
║                                                               ║
║  Starting Flask server...                                     ║
║  Open: http://127.0.0.1:5000                                 ║
║                                                               ║
║  ⚠️  Use ONLY for security awareness training!                ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
    """)
    print("Template folder:", app.template_folder)
    
    # Run Flask app
    app.run(debug=True, host='127.0.0.1', port=5000)