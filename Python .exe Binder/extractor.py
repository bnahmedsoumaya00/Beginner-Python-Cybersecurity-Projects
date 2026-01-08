"""
Executable Extractor - Educational Tool
Extracts hidden executables from polyglot files

⚠️ EDUCATIONAL USE ONLY
"""

import os
import sys
from pathlib import Path


class ExeExtractor:
    """Extracts hidden executables from bound files"""
    
    def __init__(self):
        self.start_marker = b'EXECUTABLE_START'
        self.end_marker = b'EXECUTABLE_END'
    
    def extract_exe(self, input_file, output_file=None):
        """
        Extract executable from polyglot file
        
        Args:
            input_file (str): Path to polyglot file
            output_file (str): Where to save extracted exe
            
        Returns:
            dict: Extraction results
        """
        try:
            if not os.path.exists(input_file):
                return {'success': False, 'error': 'Input file not found'}
            
            # Default output name
            if not output_file:
                base_name = Path(input_file).stem
                output_file = f"{base_name}_extracted.exe"
            
            # Read the file
            with open(input_file, 'rb') as f:
                data = f.read()
            
            # Find start marker
            start_idx = data.find(self.start_marker)
            if start_idx == -1:
                return {
                    'success': False,
                    'error': 'No executable marker found (not a bound file)'
                }
            
            # Find end marker
            end_idx = data.find(self.end_marker, start_idx)
            if end_idx == -1:
                return {
                    'success': False,
                    'error': 'Incomplete executable data (end marker not found)'
                }
            
            # Extract executable data
            exe_start = start_idx + len(self.start_marker) + 16  # Skip marker and padding
            exe_end = end_idx
            exe_data = data[exe_start:exe_end]
            
            # Save extracted executable
            with open(output_file, 'wb') as f:
                f.write(exe_data)
            
            return {
                'success': True,
                'input_file': input_file,
                'output_file': output_file,
                'exe_size': len(exe_data),
                'start_position': exe_start,
                'end_position': exe_end
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def extract_all_pe_executables(self, input_file, output_dir='extracted'):
        """
        Extract all PE executables found in file
        
        Args:
            input_file (str): File to scan
            output_dir (str): Directory for extracted files
            
        Returns:
            dict: Extraction results
        """
        try:
            # Create output directory
            os.makedirs(output_dir, exist_ok=True)
            
            with open(input_file, 'rb') as f:
                data = f.read()
            
            # Find all MZ signatures (PE executable start)
            pe_positions = []
            search_pos = 0
            
            while True:
                pos = data.find(b'MZ', search_pos)
                if pos == -1:
                    break
                pe_positions.append(pos)
                search_pos = pos + 1
            
            extracted_files = []
            
            for idx, pos in enumerate(pe_positions):
                # Try to extract PE file
                # This is simplified - real PE parsing is more complex
                try:
                    # Extract from MZ to end of file or next MZ
                    if idx + 1 < len(pe_positions):
                        exe_data = data[pos:pe_positions[idx + 1]]
                    else:
                        exe_data = data[pos:]
                    
                    output_file = os.path.join(output_dir, f'extracted_{idx}.exe')
                    
                    with open(output_file, 'wb') as f:
                        f.write(exe_data)
                    
                    extracted_files.append({
                        'file': output_file,
                        'size': len(exe_data),
                        'position': pos
                    })
                    
                except Exception as e:
                    print(f"Error extracting at position {pos}: {e}")
            
            return {
                'success': True,
                'extracted_count': len(extracted_files),
                'files': extracted_files
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }


def main():
    """Command-line interface"""
    print("""
    ╔═══════════════════════════════════════════════════════════╗
    ║                                                           ║
    ║         EXECUTABLE EXTRACTOR - Educational Tool          ║
    ║                                                           ║
    ║  ⚠️  FOR EDUCATIONAL PURPOSES ONLY ⚠️                    ║
    ║                                                           ║
    ╚═══════════════════════════════════════════════════════════╝
    """)
    
    if len(sys.argv) < 2:
        print("Usage: python extractor.py <input_file> [output_file]")
        print("\nExample:")
        print("  python extractor.py infected.png extracted.exe")
        print("\nOptions:")
        print("  --all    Extract all PE executables found")
        return
    
    input_file = sys.argv[1]
    
    if not os.path.exists(input_file):
        print(f"[✗] File not found: {input_file}")
        return
    
    extractor = ExeExtractor()
    
    if '--all' in sys.argv:
        print(f"\n[*] Scanning for all executables in: {input_file}")
        result = extractor.extract_all_pe_executables(input_file)
        
        if result['success']:
            print(f"\n[✓] Extraction complete!")
            print(f"    Found: {result['extracted_count']} executable(s)")
            for file_info in result['files']:
                print(f"    • {file_info['file']} ({file_info['size']:,} bytes)")
        else:
            print(f"\n[✗] Extraction failed: {result.get('error')}")
    
    else:
        output_file = sys.argv[2] if len(sys.argv) > 2 else None
        
        print(f"\n[*] Extracting executable from: {input_file}")
        result = extractor.extract_exe(input_file, output_file)
        
        if result['success']:
            print(f"\n[✓] Extraction successful!")
            print(f"    Output: {result['output_file']}")
            print(f"    Size: {result['exe_size']:,} bytes")
            print(f"    Position: {result['start_position']:,} to {result['end_position']:,}")
            print(f"\n⚠️  WARNING: Do not run extracted executables unless you trust the source!")
        else:
            print(f"\n[✗] Extraction failed: {result.get('error')}")


if __name__ == '__main__':
    main()