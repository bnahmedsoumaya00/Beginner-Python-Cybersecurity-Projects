from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from functools import wraps
import json
import os
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'educational_demo_key_change_in_production'

# Educational mode flag
TRAINING_MODE = True
DATA_FILE = 'captured_credentials.json'


# ==================== HELPER FUNCTIONS ====================

def save_captured_data(data):
    """Save captured data to JSON file"""
    try:
        # Load existing data
        if os.path.exists(DATA_FILE):
            with open(DATA_FILE, 'r') as f:
                captured_data = json.load(f)
        else:
            captured_data = []
        
        # Add new entry
        entry = {
            'timestamp': datetime.now().isoformat(),
            'data': data,
            'user_agent': request.headers.get('User-Agent', 'Unknown'),
            'ip_address': request.remote_addr
        }
        captured_data.append(entry)
        
        # Save to file
        with open(DATA_FILE, 'w') as f:
            json.dump(captured_data, f, indent=2)
        
        return True
    except Exception as e:
        print(f"Error saving data: {e}")
        return False


def load_captured_data():
    """Load captured data from JSON file"""
    try:
        if os.path.exists(DATA_FILE):
            with open(DATA_FILE, 'r') as f:
                return json.load(f)
        return []
    except Exception as e:
        print(f"Error loading data: {e}")
        return []


def educational_warning(f):
    """Decorator to ensure educational warning has been acknowledged"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('educational_acknowledged'):
            return redirect(url_for('warning'))
        return f(*args, **kwargs)
    return decorated_function


# ==================== MAIN ROUTES ====================

@app.route('/')
@educational_warning
def index():
    """Homepage"""
    return render_template('index.html')


@app.route('/warning')
def warning():
    """Educational warning page"""
    return render_template('warning.html')


@app.route('/acknowledge-educational', methods=['POST'])
def acknowledge_educational():
    """Process educational warning acknowledgment"""
    # Check all required checkboxes
    required_checks = [
        'educational_use',
        'local_only',
        'no_phishing',
        'understand_illegal',
        'accept_responsibility',
        'protect_not_harm'
    ]
    
    # Debug: Print what we received
    print("Form data received:")
    for key in request.form:
        print(f"  {key}: {request.form.get(key)}")
    
    all_checked = all(request.form.get(check) == 'on' for check in required_checks)
    
    print(f"All checked: {all_checked}")
    
    if all_checked:
        session['educational_acknowledged'] = True
        flash('Thank you for acknowledging the educational purpose of this tool.', 'success')
        return redirect(url_for('index'))
    else:
        # Show which ones are missing
        missing = [check for check in required_checks if request.form.get(check) != 'on']
        print(f"Missing checkboxes: {missing}")
        flash('You must acknowledge all statements to proceed.', 'danger')
        return redirect(url_for('warning'))


# ==================== DEMO ROUTES ====================

@app.route('/demo-selector')
@educational_warning
def demo_selector():
    """Demo platform selector"""
    return render_template('demo_selector.html')


@app.route('/demo/<platform>')
@educational_warning
def demo_platform(platform):
    """Display demo for specified platform"""
    valid_platforms = ['google', 'facebook', 'linkedin', 'github', 'banking']
    
    if platform.lower() not in valid_platforms:
        flash('Invalid demo platform selected.', 'danger')
        return redirect(url_for('demo_selector'))
    
    return render_template(f'demos/{platform.lower()}_login.html')


# ==================== TRAINING ROUTES ====================

@app.route('/training')
@educational_warning
def training():
    """Security awareness training"""
    return render_template('training.html')


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


# ==================== NEW PROJECT 6 ROUTES ====================

@app.route('/campaign')
@educational_warning
def campaign():
    """Phishing campaign scenarios"""
    return render_template('campaign.html')


@app.route('/email-templates')
@educational_warning
def email_templates():
    """Show common phishing email templates"""
    return render_template('email_templates.html')


@app.route('/quiz')
@educational_warning
def quiz():
    """Phishing detection quiz"""
    return render_template('quiz.html')


@app.route('/analytics')
@educational_warning
def analytics():
    """Analytics on phishing effectiveness"""
    return render_template('analytics.html')


@app.route('/resources')
@educational_warning
def resources():
    """Downloadable campaign resources"""
    return render_template('resources.html')


# ==================== DATA ROUTES ====================

@app.route('/capture', methods=['POST'])
@educational_warning
def capture_credentials():
    """Capture form submission"""
    platform = request.form.get('platform', 'Unknown')
    
    # Prepare data (don't store actual password)
    data = {
        'platform': platform,
        'email': request.form.get('email', ''),
        'username': request.form.get('username', ''),
        'password': '***HIDDEN***',  # Never store actual password
        'password_length': len(request.form.get('password', '')),
    }
    
    # Save captured data
    save_captured_data(data)
    
    # NEW: Store redirect URL for the success page
    REDIRECT_URLS = {
        'Google': 'https://accounts.google.com',
        'Facebook': 'https://www.facebook.com',
        'LinkedIn': 'https://www.linkedin.com',
        'GitHub': 'https://github.com/login',
        'Banking': 'https://www.example.com'
    }
    session['redirect_url'] = REDIRECT_URLS.get(platform, 'https://www.google.com')
    
    flash(f'⚠️ EDUCATIONAL DEMO: Credentials captured from {platform}!', 'warning')
    
    return redirect(url_for('capture_success'))


@app.route('/capture-success')
@educational_warning
def capture_success():
    """Post-capture educational message"""
    return render_template('capture_success.html')


@app.route('/dashboard')
@educational_warning
def dashboard():
    """Analytics dashboard"""
    captured = load_captured_data()
    return render_template('dashboard.html', captured=captured, count=len(captured))


@app.route('/api/stats')
@educational_warning
def api_stats():
    """Return statistics as JSON"""
    data = load_captured_data()
    
    stats = {
        'total_captures': len(data),
        'platforms': {},
        'timestamps': []
    }
    
    for item in data:
        platform = item.get('data', {}).get('platform', 'Unknown')
        stats['platforms'][platform] = stats['platforms'].get(platform, 0) + 1
        stats['timestamps'].append(item.get('timestamp', ''))
    
    return jsonify(stats)


@app.route('/api/clear-data', methods=['POST'])
@educational_warning
def api_clear_data():
    """Clear all captured data"""
    try:
        if os.path.exists(DATA_FILE):
            os.remove(DATA_FILE)
        flash('All data has been cleared.', 'success')
    except Exception as e:
        flash(f'Error clearing data: {e}', 'danger')
    
    return redirect(url_for('dashboard'))


# ==================== ERROR HANDLERS ====================

@app.errorhandler(404)
def not_found(e):
    """404 error handler"""
    return render_template('404.html'), 404


@app.errorhandler(500)
def server_error(e):
    """500 error handler"""
    return render_template('500.html'), 500


# ==================== RUN APPLICATION ====================

if __name__ == '__main__':
    print("""
    ╔═══════════════════════════════════════════════════════════╗
    ║                                                           ║
    ║        PHISHING AWARENESS CAMPAIGN - Project 6           ║
    ║           Educational Security Training Tool             ║
    ║                                                           ║
    ║  ⚠️  FOR EDUCATIONAL PURPOSES ONLY ⚠️                    ║
    ║                                                           ║
    ║  Running on: http://127.0.0.1:5000                       ║
    ║                                                           ║
    ║  Features:                                               ║
    ║  • 5 Phishing Demos                                      ║
    ║  • Campaign Scenarios                                    ║
    ║  • Email Templates                                       ║
    ║  • Interactive Quiz                                      ║
    ║  • Training Modules                                      ║
    ║  • Analytics Dashboard                                   ║
    ║                                                           ║
    ╚═══════════════════════════════════════════════════════════╝
    """)
    
    app.run(debug=True, host='127.0.0.1', port=5000)