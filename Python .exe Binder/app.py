"""
Python .exe Binder - Flask Web Interface
Educational demonstration of polyglot files

⚠️ FOR EDUCATIONAL PURPOSES ONLY
"""

from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file, jsonify
from werkzeug.utils import secure_filename
from functools import wraps
import os
import json
from datetime import datetime

# Import our tools
from binder import ExeBinder
from detector import FileDetector
from extractor import ExeExtractor

app = Flask(__name__)
app.secret_key = 'educational_polyglot_demo_key_change_in_production'

# Configuration
UPLOAD_FOLDER = 'uploads'
OUTPUT_FOLDER = 'outputs'
ALLOWED_IMAGE_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'bmp'}
ALLOWED_EXE_EXTENSIONS = {'exe', 'py'}
MAX_FILE_SIZE = 50 * 1024 * 1024  # 50MB

# Create folders
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(OUTPUT_FOLDER, exist_ok=True)

# Initialize tools
binder = ExeBinder()
detector = FileDetector()
extractor = ExeExtractor()


def educational_warning(f):
    """Decorator to ensure educational warning has been acknowledged"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('educational_acknowledged'):
            return redirect(url_for('warning'))
        return f(*args, **kwargs)
    return decorated_function


def allowed_file(filename, allowed_extensions):
    """Check if file extension is allowed"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_extensions


# ==================== ROUTES ====================

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
    required_checks = [
        'educational_use',
        'local_only',
        'no_malware',
        'understand_illegal',
        'accept_responsibility',
        'protect_not_harm'
    ]
    
    all_checked = all(request.form.get(check) == 'on' for check in required_checks)
    
    if all_checked:
        session['educational_acknowledged'] = True
        flash('Thank you for acknowledging the educational purpose of this tool.', 'success')
        return redirect(url_for('index'))
    else:
        flash('You must acknowledge all statements to proceed.', 'danger')
        return redirect(url_for('warning'))


@app.route('/binder')
@educational_warning
def binder_page():
    """Binder tool page"""
    return render_template('binder.html')


@app.route('/bind', methods=['POST'])
@educational_warning
def bind_files():
    """Process file binding"""
    try:
        # Check if files are present
        if 'image' not in request.files or 'executable' not in request.files:
            flash('Both image and executable files are required.', 'danger')
            return redirect(url_for('binder_page'))
        
        image_file = request.files['image']
        exe_file = request.files['executable']
        
        # Validate filenames
        if image_file.filename == '' or exe_file.filename == '':
            flash('Please select both files.', 'danger')
            return redirect(url_for('binder_page'))
        
        # Check extensions
        if not allowed_file(image_file.filename, ALLOWED_IMAGE_EXTENSIONS):
            flash('Invalid image file type.', 'danger')
            return redirect(url_for('binder_page'))
        
        if not allowed_file(exe_file.filename, ALLOWED_EXE_EXTENSIONS):
            flash('Invalid executable file type.', 'danger')
            return redirect(url_for('binder_page'))
        
        # Save uploaded files
        image_filename = secure_filename(image_file.filename)
        exe_filename = secure_filename(exe_file.filename)
        
        image_path = os.path.join(UPLOAD_FOLDER, image_filename)
        exe_path = os.path.join(UPLOAD_FOLDER, exe_filename)
        
        image_file.save(image_path)
        exe_file.save(exe_path)
        
        # Generate output filename
        output_filename = f"bound_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{image_filename}"
        output_path = os.path.join(OUTPUT_FOLDER, output_filename)
        
        # Bind files
        method = request.form.get('method', 'concat')
        
        if method == 'zip':
            result = binder.bind_with_zip(image_path, exe_path, output_path)
        else:
            result = binder.bind_exe_to_image(image_path, exe_path, output_path)
        
        if result['success']:
            flash('Files successfully bound! ⚠️ This file now contains hidden executable code.', 'success')
            
            # Store result in session
            session['last_bound_file'] = output_filename
            session['bind_result'] = {
                'output_file': output_filename,
                'original_image': image_filename,
                'executable': exe_filename,
                'method': method,
                'size': result.get('final_size', 0)
            }
            
            return redirect(url_for('bind_success'))
        else:
            flash(f'Binding failed: {result.get("error")}', 'danger')
            return redirect(url_for('binder_page'))
        
    except Exception as e:
        flash(f'Error: {str(e)}', 'danger')
        return redirect(url_for('binder_page'))


@app.route('/bind-success')
@educational_warning
def bind_success():
    """Binding success page"""
    result = session.get('bind_result')
    if not result:
        return redirect(url_for('binder_page'))
    
    return render_template('bind_success.html', result=result)


@app.route('/download/<filename>')
@educational_warning
def download_file(filename):
    """Download bound file"""
    try:
        file_path = os.path.join(OUTPUT_FOLDER, secure_filename(filename))
        if os.path.exists(file_path):
            return send_file(file_path, as_attachment=True)
        else:
            flash('File not found.', 'danger')
            return redirect(url_for('index'))
    except Exception as e:
        flash(f'Download error: {str(e)}', 'danger')
        return redirect(url_for('index'))


@app.route('/detector')
@educational_warning
def detector_page():
    """Detector tool page"""
    return render_template('detector.html')


@app.route('/detect', methods=['POST'])
@educational_warning
def detect_file():
    """Analyze uploaded file"""
    try:
        if 'file' not in request.files:
            flash('No file uploaded.', 'danger')
            return redirect(url_for('detector_page'))
        
        file = request.files['file']
        
        if file.filename == '':
            flash('No file selected.', 'danger')
            return redirect(url_for('detector_page'))
        
        # Save file
        filename = secure_filename(file.filename)
        file_path = os.path.join(UPLOAD_FOLDER, f"scan_{filename}")
        file.save(file_path)
        
        # Analyze file
        results = detector.analyze_file(file_path)
        
        # Store results in session
        session['detection_results'] = results
        
        return redirect(url_for('detection_results'))
        
    except Exception as e:
        flash(f'Detection error: {str(e)}', 'danger')
        return redirect(url_for('detector_page'))


@app.route('/detection-results')
@educational_warning
def detection_results():
    """Show detection results"""
    results = session.get('detection_results')
    if not results:
        return redirect(url_for('detector_page'))
    
    return render_template('detection_results.html', results=results)


@app.route('/learning')
@educational_warning
def learning():
    """Educational content page"""
    return render_template('learning.html')


@app.route('/signatures')
@educational_warning
def signatures():
    """File signature reference"""
    return render_template('signatures.html')


@app.route('/extractor')
@educational_warning
def extractor_page():
    """Extractor tool page"""
    return render_template('extractor.html')


@app.route('/extract', methods=['POST'])
@educational_warning
def extract_file():
    """Extract executable from file"""
    try:
        if 'file' not in request.files:
            flash('No file uploaded.', 'danger')
            return redirect(url_for('extractor_page'))
        
        file = request.files['file']
        
        if file.filename == '':
            flash('No file selected.', 'danger')
            return redirect(url_for('extractor_page'))
        
        # Save file
        filename = secure_filename(file.filename)
        input_path = os.path.join(UPLOAD_FOLDER, f"extract_{filename}")
        file.save(input_path)
        
        # Extract
        output_filename = f"extracted_{datetime.now().strftime('%Y%m%d_%H%M%S')}.exe"
        output_path = os.path.join(OUTPUT_FOLDER, output_filename)
        
        result = extractor.extract_exe(input_path, output_path)
        
        if result['success']:
            flash('Executable extracted successfully! ⚠️ Do not run unless you trust the source.', 'warning')
            session['extracted_file'] = output_filename
            session['extraction_result'] = result
            return redirect(url_for('extraction_success'))
        else:
            flash(f'Extraction failed: {result.get("error")}', 'danger')
            return redirect(url_for('extractor_page'))
        
    except Exception as e:
        flash(f'Extraction error: {str(e)}', 'danger')
        return redirect(url_for('extractor_page'))


@app.route('/extraction-success')
@educational_warning
def extraction_success():
    """Extraction success page"""
    result = session.get('extraction_result')
    if not result:
        return redirect(url_for('extractor_page'))
    
    return render_template('extraction_success.html', result=result)


# ==================== ERROR HANDLERS ====================

@app.errorhandler(404)
def not_found(e):
    return render_template('404.html'), 404


@app.errorhandler(500)
def server_error(e):
    return render_template('500.html'), 500


# ==================== RUN APPLICATION ====================

if __name__ == '__main__':
    print("""
    ╔═══════════════════════════════════════════════════════════╗
    ║                                                           ║
    ║        PYTHON .EXE BINDER - Educational Platform         ║
    ║              Polyglot File Demonstration                 ║
    ║                                                           ║
    ║  ⚠️  FOR EDUCATIONAL PURPOSES ONLY ⚠️                    ║
    ║                                                           ║
    ║  Running on: http://127.0.0.1:5000                       ║
    ║                                                           ║
    ║  Features:                                               ║
    ║  • File Binder (hide exe in images)                     ║
    ║  • File Detector (find hidden executables)              ║
    ║  • Extractor (extract hidden exe)                       ║
    ║  • Learning Materials (file signatures)                 ║
    ║                                                           ║
    ╚═══════════════════════════════════════════════════════════╝
    """)
    
    app.run(debug=True, host='127.0.0.1', port=5000)