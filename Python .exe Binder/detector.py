"""
File Signature Detector - Educational Tool
Detects polyglot files and hidden executables

⚠️ EDUCATIONAL USE ONLY
"""

import os
import struct
from pathlib import Path


class FileDetector:
    """Detects suspicious files and analyzes file signatures"""
    
    # Known file signatures (magic bytes)
    SIGNATURES = {
        # Images
        'PNG': b'\x89\x50\x4E\x47\x0D\x0A\x1A\x0A',
        'JPEG': b'\xFF\xD8\xFF',
        'GIF87': b'GIF87a',
        'GIF89': b'GIF89a',
        'BMP': b'BM',
        
        # Executables
        'PE_EXE': b'MZ',  # Windows PE executable
        'ELF': b'\x7F\x45\x4C\x46',  # Linux ELF
        
        # Archives
        'ZIP': b'PK\x03\x04',
        'RAR': b'Rar!\x1A\x07',
        
        # Documents
        'PDF': b'%PDF',
    }
    
    def __init__(self):
        self.markers = [
            b'EXECUTABLE_START',
            b'EXECUTABLE_END',
            b'MZ',  # PE executable signature
        ]
    
    def read_file_header(self, file_path, bytes_to_read=16):
        """Read file header bytes"""
        try:
            with open(file_path, 'rb') as f:
                return f.read(bytes_to_read)
        except Exception as e:
            return None
    
    def identify_file_type(self, file_path):
        """
        Identify file type by signature
        
        Args:
            file_path (str): Path to file
            
        Returns:
            list: Detected file types
        """
        header = self.read_file_header(file_path, 32)
        if not header:
            return []
        
        detected_types = []
        
        for file_type, signature in self.SIGNATURES.items():
            if header.startswith(signature):
                detected_types.append(file_type)
        
        return detected_types
    
    def scan_for_embedded_exe(self, file_path):
        """
        Scan file for embedded executables
        
        Args:
            file_path (str): Path to file to scan
            
        Returns:
            dict: Detection results
        """
        try:
            file_size = os.path.getsize(file_path)
            
            # Read file in chunks
            chunk_size = 1024 * 1024  # 1MB chunks
            exe_found = False
            exe_positions = []
            
            with open(file_path, 'rb') as f:
                position = 0
                
                while True:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break
                    
                    # Look for PE executable signature (MZ)
                    if b'MZ' in chunk:
                        idx = chunk.find(b'MZ')
                        exe_positions.append(position + idx)
                        exe_found = True
                    
                    # Look for our markers
                    if b'EXECUTABLE_START' in chunk:
                        idx = chunk.find(b'EXECUTABLE_START')
                        exe_positions.append(('marker', position + idx))
                    
                    position += len(chunk)
            
            # Get file extension
            extension = Path(file_path).suffix.lower()
            
            # Determine if suspicious
            is_suspicious = False
            reasons = []
            
            if exe_found and extension in ['.png', '.jpg', '.jpeg', '.gif', '.bmp']:
                is_suspicious = True
                reasons.append("Executable signature found in image file")
            
            if len(exe_positions) > 1:
                is_suspicious = True
                reasons.append("Multiple executable signatures detected")
            
            # Check file size vs expected size
            expected_size = self._estimate_image_size(file_path)
            if expected_size and file_size > expected_size * 1.5:
                is_suspicious = True
                reasons.append(f"File size ({file_size:,} bytes) larger than expected")
            
            return {
                'file_path': file_path,
                'file_size': file_size,
                'extension': extension,
                'executable_found': exe_found,
                'exe_positions': exe_positions,
                'is_suspicious': is_suspicious,
                'reasons': reasons,
                'file_types': self.identify_file_type(file_path)
            }
            
        except Exception as e:
            return {
                'error': str(e),
                'file_path': file_path
            }
    
    def _estimate_image_size(self, file_path):
        """Estimate expected size for an image based on dimensions"""
        # Simplified estimation
        # Real implementation would parse image headers
        return None
    
    def analyze_file(self, file_path):
        """
        Comprehensive file analysis
        
        Args:
            file_path (str): Path to analyze
            
        Returns:
            dict: Complete analysis results
        """
        results = {
            'file_path': file_path,
            'file_name': os.path.basename(file_path),
            'file_size': os.path.getsize(file_path),
            'extension': Path(file_path).suffix.lower(),
        }
        
        # Read header
        header = self.read_file_header(file_path, 64)
        if header:
            results['header_hex'] = header[:32].hex()
            results['header_ascii'] = ''.join(chr(b) if 32 <= b < 127 else '.' for b in header[:32])
        
        # Identify file types
        results['detected_types'] = self.identify_file_type(file_path)
        
        # Scan for embedded executables
        scan_result = self.scan_for_embedded_exe(file_path)
        results.update(scan_result)
        
        return results


def main():
    """Command-line interface"""
    import sys
    
    print("""
    ╔═══════════════════════════════════════════════════════════╗
    ║                                                           ║
    ║           FILE DETECTOR - Educational Tool               ║
    ║                                                           ║
    ║  Detects polyglot files and hidden executables          ║
    ║                                                           ║
    ╚═══════════════════════════════════════════════════════════╝
    """)
    
    if len(sys.argv) < 2:
        print("Usage: python detector.py <file_path>")
        print("\nExample:")
        print("  python detector.py suspicious_image.png")
        return
    
    file_path = sys.argv[1]
    
    if not os.path.exists(file_path):
        print(f"[✗] File not found: {file_path}")
        return
    
    detector = FileDetector()
    print(f"\n[*] Analyzing file: {file_path}\n")
    
    results = detector.analyze_file(file_path)
    
    # Display results
    print("=" * 60)
    print("FILE INFORMATION")
    print("=" * 60)
    print(f"  File: {results['file_name']}")
    print(f"  Size: {results['file_size']:,} bytes")
    print(f"  Extension: {results['extension']}")
    print(f"\n  Detected Types: {', '.join(results['detected_types']) if results['detected_types'] else 'Unknown'}")
    
    if 'header_hex' in results:
        print(f"\n  Header (hex): {results['header_hex']}")
        print(f"  Header (ASCII): {results['header_ascii']}")
    
    print("\n" + "=" * 60)
    print("ANALYSIS RESULTS")
    print("=" * 60)
    
    if results.get('is_suspicious'):
        print("\n  🚨 SUSPICIOUS FILE DETECTED!\n")
        print("  Reasons:")
        for reason in results.get('reasons', []):
            print(f"    • {reason}")
        
        if results.get('exe_positions'):
            print(f"\n  Executable signatures found at positions:")
            for pos in results['exe_positions']:
                if isinstance(pos, tuple):
                    print(f"    • {pos[0]}: byte {pos[1]:,}")
                else:
                    print(f"    • Byte {pos:,}")
    else:
        print("\n  ✓ File appears normal (no hidden executables detected)")
    
    print("\n" + "=" * 60)


if __name__ == '__main__':
    main()