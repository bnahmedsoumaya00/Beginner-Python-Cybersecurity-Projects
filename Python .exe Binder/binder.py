"""
Python .exe Binder - Educational Tool
Demonstrates polyglot file creation for security awareness

⚠️ EDUCATIONAL USE ONLY - Never use for malware distribution
"""

import os
import sys
from pathlib import Path
import zipfile
import shutil


class ExeBinder:
    """Binds executable files to images creating polyglot files"""
    
    def __init__(self):
        self.supported_images = ['.png', '.jpg', '.jpeg', '.gif', '.bmp']
        
    def bind_exe_to_image(self, image_path, exe_path, output_path):
        """
        Bind an executable to an image file
        
        Args:
            image_path (str): Path to source image
            exe_path (str): Path to executable
            output_path (str): Path for output file
            
        Returns:
            dict: Results with success status and details
        """
        try:
            # Validate inputs
            if not os.path.exists(image_path):
                return {'success': False, 'error': 'Image file not found'}
            
            if not os.path.exists(exe_path):
                return {'success': False, 'error': 'Executable file not found'}
            
            # Check file extensions
            image_ext = Path(image_path).suffix.lower()
            if image_ext not in self.supported_images:
                return {'success': False, 'error': f'Unsupported image format: {image_ext}'}
            
            # Get file sizes
            image_size = os.path.getsize(image_path)
            exe_size = os.path.getsize(exe_path)
            
            # Method 1: Simple concatenation
            # This creates a polyglot file that is both a valid image and contains the exe
            
            # Copy image to output
            shutil.copy2(image_path, output_path)
            
            # Append executable data
            with open(output_path, 'ab') as output_file:
                with open(exe_path, 'rb') as exe_file:
                    # Write a separator marker
                    separator = b'\x00' * 16 + b'EXECUTABLE_START' + b'\x00' * 16
                    output_file.write(separator)
                    
                    # Write the executable
                    output_file.write(exe_file.read())
                    
                    # Write end marker
                    end_marker = b'\x00' * 16 + b'EXECUTABLE_END' + b'\x00' * 16
                    output_file.write(end_marker)
            
            # Get final size
            final_size = os.path.getsize(output_path)
            
            return {
                'success': True,
                'image_path': image_path,
                'exe_path': exe_path,
                'output_path': output_path,
                'original_image_size': image_size,
                'exe_size': exe_size,
                'final_size': final_size,
                'size_increase': final_size - image_size,
                'method': 'concatenation'
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def bind_with_zip(self, image_path, exe_path, output_path):
        """
        Alternative method: Create a ZIP archive disguised as image
        
        Args:
            image_path (str): Path to source image
            exe_path (str): Path to executable
            output_path (str): Path for output file
            
        Returns:
            dict: Results with success status and details
        """
        try:
            # Create temporary ZIP file
            temp_zip = output_path + '.temp.zip'
            
            # Create ZIP with image and exe
            with zipfile.ZipFile(temp_zip, 'w', zipfile.ZIP_DEFLATED) as zipf:
                zipf.write(image_path, os.path.basename(image_path))
                zipf.write(exe_path, os.path.basename(exe_path))
            
            # Rename to image extension (polyglot file)
            os.rename(temp_zip, output_path)
            
            return {
                'success': True,
                'output_path': output_path,
                'method': 'zip_polyglot',
                'note': 'File is both a valid ZIP and has image extension'
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def create_test_executable(self, output_path):
        """
        Create a simple test executable for demonstration
        
        Args:
            output_path (str): Where to save the test exe
            
        Returns:
            bool: Success status
        """
        try:
            # Simple Python script
            script_content = '''
import sys
import tkinter as tk
from tkinter import messagebox

def main():
    root = tk.Tk()
    root.withdraw()
    messagebox.showinfo(
        "Educational Demo", 
        "This is a test executable extracted from an image!\\n\\n"
        "⚠️ In a real attack, this could be malware.\\n"
        "Always verify file sources!"
    )
    root.destroy()

if __name__ == "__main__":
    main()
'''
            
            # Save script
            script_path = output_path.replace('.exe', '.py')
            with open(script_path, 'w') as f:
                f.write(script_content)
            
            # Note: To create actual .exe, would need PyInstaller
            # For this demo, we'll use the .py file
            
            print(f"Test script created: {script_path}")
            print("To create .exe, run: pyinstaller --onefile --windowed " + script_path)
            
            return True
            
        except Exception as e:
            print(f"Error creating test executable: {e}")
            return False


def main():
    """Command-line interface for the binder"""
    binder = ExeBinder()
    
    print("""
    ╔═══════════════════════════════════════════════════════════╗
    ║                                                           ║
    ║           PYTHON .EXE BINDER - Educational Tool          ║
    ║                                                           ║
    ║  ⚠️  FOR EDUCATIONAL PURPOSES ONLY ⚠️                    ║
    ║                                                           ║
    ╚═══════════════════════════════════════════════════════════╝
    """)
    
    if len(sys.argv) < 4:
        print("Usage: python binder.py <image_path> <exe_path> <output_path>")
        print("\nExample:")
        print("  python binder.py photo.png program.exe infected.png")
        print("\nOptions:")
        print("  --method zip    Use ZIP polyglot method")
        return
    
    image_path = sys.argv[1]
    exe_path = sys.argv[2]
    output_path = sys.argv[3]
    
    method = 'concat'
    if '--method' in sys.argv:
        idx = sys.argv.index('--method')
        if idx + 1 < len(sys.argv):
            method = sys.argv[idx + 1]
    
    print(f"\n[*] Binding executable to image...")
    print(f"    Image: {image_path}")
    print(f"    Executable: {exe_path}")
    print(f"    Output: {output_path}")
    print(f"    Method: {method}")
    
    if method == 'zip':
        result = binder.bind_with_zip(image_path, exe_path, output_path)
    else:
        result = binder.bind_exe_to_image(image_path, exe_path, output_path)
    
    if result['success']:
        print("\n[✓] Binding successful!")
        print(f"\n    Output file: {result.get('output_path')}")
        if 'original_image_size' in result:
            print(f"    Original image: {result['original_image_size']:,} bytes")
            print(f"    Executable: {result['exe_size']:,} bytes")
            print(f"    Final size: {result['final_size']:,} bytes")
            print(f"    Size increase: {result['size_increase']:,} bytes")
        print(f"\n⚠️  This file now contains hidden executable code!")
    else:
        print(f"\n[✗] Binding failed: {result.get('error')}")


if __name__ == '__main__':
    main()