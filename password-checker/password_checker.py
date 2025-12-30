"""
Password Strength Checker & Generator
Project 1 - Cybersecurity Python Roadmap
Author: bnahmedsoumaya00
Date: December 29, 2025
"""

import string
import secrets
import re
import math
from tkinter import *
from tkinter import ttk, messagebox


def calculate_entropy(password):
    """Calculate password entropy in bits"""
    pool_size = 0
    
    # Check character types used
    if any(c. islower() for c in password):
        pool_size += 26  # lowercase letters
    if any(c.isupper() for c in password):
        pool_size += 26  # uppercase letters
    if any(c.isdigit() for c in password):
        pool_size += 10  # digits
    if any(c in string.punctuation for c in password):
        pool_size += 32  # special characters
    
    if pool_size == 0:
        return 0
    
    # Entropy = length × log2(pool_size)
    entropy = len(password) * math.log2(pool_size)
    return entropy


def estimate_crack_time(entropy):
    """Estimate time to crack password assuming 1 billion guesses/second"""
    guesses_per_second = 1_000_000_000
    total_combinations = 2 ** entropy
    seconds = total_combinations / (2 * guesses_per_second)  # Average case
    
    # Convert to human-readable format
    if seconds < 60:
        return f"{seconds:.2f} seconds"
    elif seconds < 3600:
        return f"{seconds/60:.2f} minutes"
    elif seconds < 86400:
        return f"{seconds/3600:.2f} hours"
    elif seconds < 31536000:
        return f"{seconds/86400:.2f} days"
    else:
        years = seconds / 31536000
        if years > 1e100:
            return "Practically uncrackable (> 10^100 years)"
        return f"{years:.2e} years"


def analyze_password(password):
    """Analyze password and return detailed results"""
    if not password:
        return None
    
    # Basic checks
    length = len(password)
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_symbol = any(c in string.punctuation for c in password)
    
    # Pattern detection
    is_sequential = bool(re.search(r'(abc|bcd|cde|123|234|345|678|789|012)', 
                                   password. lower()))
    is_repeated = bool(re.search(r'(.)\1{2,}', password))
    
    # Common weak passwords
    common_passwords = ['password', '123456', 'qwerty', 'admin', 'letmein']
    is_common = password. lower() in common_passwords
    
    # Calculate security metrics
    entropy = calculate_entropy(password)
    crack_time = estimate_crack_time(entropy)
    
    # Score the password (0-10)
    score = 0
    if length >= 8:  score += 1
    if length >= 12: score += 1
    if length >= 16: score += 1
    if has_upper: score += 1
    if has_lower: score += 1
    if has_digit: score += 1
    if has_symbol: score += 1
    if not is_sequential: score += 1
    if not is_repeated: score += 1
    if not is_common: score += 1
    
    # Determine strength level
    if score <= 3:
        strength = "WEAK"
        color = "red"
    elif score <= 6:
        strength = "MODERATE"
        color = "orange"
    else:
        strength = "STRONG"
        color = "green"
    
    return {
        'length': length,
        'has_upper': has_upper,
        'has_lower': has_lower,
        'has_digit':  has_digit,
        'has_symbol': has_symbol,
        'is_sequential': is_sequential,
        'is_repeated': is_repeated,
        'is_common': is_common,
        'entropy': entropy,
        'crack_time': crack_time,
        'score': score,
        'strength':  strength,
        'color': color
    }


class PasswordToolApp:
    """Main application class"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("Password Strength Checker & Generator")
        self.root.geometry("700x600")
        self.root.resizable(False, False)
        
        # Create notebook (tabs)
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill=BOTH, expand=True, padx=10, pady=10)
        
        # Create tabs
        self.checker_frame = Frame(self.notebook, bg='white')
        self.generator_frame = Frame(self.notebook, bg='white')
        
        self.notebook.add(self.checker_frame, text="  Check Password  ")
        self.notebook.add(self.generator_frame, text="  Generate Password  ")
        
        # Setup both tabs
        self.setup_checker_tab()
        self.setup_generator_tab()
    
    def setup_checker_tab(self):
        """Setup the password checking interface"""
        # Title
        title = Label(self.checker_frame, text="🔐 Password Strength Checker",
                     font=("Arial", 16, "bold"), bg='white', fg='#2c3e50')
        title.pack(pady=20)
        
        # Instructions
        instruction = Label(self.checker_frame, 
                          text="Enter a password to analyze its strength:",
                          font=("Arial", 10), bg='white', fg='#7f8c8d')
        instruction.pack(pady=5)
        
        # Password input frame
        input_frame = Frame(self.checker_frame, bg='white')
        input_frame.pack(pady=10)
        
        self.password_entry = Entry(input_frame, width=40, 
                                    font=("Courier", 12), show="*",
                                    relief=SOLID, borderwidth=1)
        self.password_entry.pack(side=LEFT, padx=5)
        
        # Show/Hide button
        self.show_password_var = BooleanVar()
        self.toggle_btn = Checkbutton(input_frame, text="👁️ Show",
                                      variable=self.show_password_var,
                                      command=self.toggle_password,
                                      bg='white', font=("Arial", 9))
        self.toggle_btn.pack(side=LEFT, padx=5)
        
        # Check button
        check_btn = Button(self.checker_frame, text="🔍 Analyze Password",
                          command=self. check_password,
                          bg='#3498db', fg='white', 
                          font=("Arial", 11, "bold"),
                          padx=30, pady=10, relief=FLAT,
                          cursor='hand2')
        check_btn.pack(pady=15)
        
        # Results frame
        results_frame = Frame(self.checker_frame, bg='white')
        results_frame. pack(fill=BOTH, expand=True, padx=20, pady=10)
        
        self.result_text = Text(results_frame, height=18, width=70,
                               font=("Courier", 10), wrap=WORD,
                               relief=SOLID, borderwidth=1,
                               padx=10, pady=10)
        self.result_text.pack(side=LEFT, fill=BOTH, expand=True)
        
        # Scrollbar
        scrollbar = Scrollbar(results_frame, command=self.result_text.yview)
        scrollbar.pack(side=RIGHT, fill=Y)
        self.result_text.config(yscrollcommand=scrollbar.set)
        
        # Initial message
        welcome_msg = """
╔══════════════════════════════════════════════════════════╗
║                                                          ║
║          Welcome to Password Strength Checker!           ║
║                                                          ║
║  Enter a password above and click 'Analyze Password'    ║
║  to see detailed security analysis.                     ║
║                                                          ║
╚══════════════════════════════════════════════════════════╝
        """
        self. result_text.insert(1.0, welcome_msg)
        self.result_text.config(state=DISABLED)
    
    def setup_generator_tab(self):
        """Setup the password generation interface"""
        # Title
        title = Label(self. generator_frame, text="🎲 Password Generator",
                     font=("Arial", 16, "bold"), bg='white', fg='#2c3e50')
        title.pack(pady=20)
        
        # Settings frame
        settings_frame = LabelFrame(self.generator_frame, text="  Generation Settings  ",
                                   font=("Arial", 11, "bold"), bg='white',
                                   padx=20, pady=15)
        settings_frame.pack(padx=20, pady=10, fill=X)
        
        # Length setting
        length_frame = Frame(settings_frame, bg='white')
        length_frame.pack(pady=10, fill=X)
        
        Label(length_frame, text="Password Length:", 
              font=("Arial", 10), bg='white').pack(side=LEFT, padx=5)
        
        self.length_var = IntVar(value=16)
        length_spin = Spinbox(length_frame, from_=4, to=128, 
                             textvariable=self.length_var,
                             width=10, font=("Arial", 10))
        length_spin.pack(side=LEFT, padx=5)
        
        self.length_label = Label(length_frame, text="(Recommended: 12-16+)",
                                 font=("Arial", 9), bg='white', fg='#7f8c8d')
        self.length_label.pack(side=LEFT, padx=5)
        
        # Character type checkboxes
        Label(settings_frame, text="Include Characters:",
              font=("Arial", 10, "bold"), bg='white').pack(anchor=W, pady=(10,5))
        
        checkbox_frame = Frame(settings_frame, bg='white')
        checkbox_frame.pack(fill=X)
        
        self.use_uppercase = BooleanVar(value=True)
        self.use_lowercase = BooleanVar(value=True)
        self.use_digits = BooleanVar(value=True)
        self.use_symbols = BooleanVar(value=True)
        
        cb1 = Checkbutton(checkbox_frame, text="✓ Uppercase (A-Z)",
                         variable=self.use_uppercase, bg='white',
                         font=("Arial", 10))
        cb1.grid(row=0, column=0, sticky=W, padx=10, pady=2)
        
        cb2 = Checkbutton(checkbox_frame, text="✓ Lowercase (a-z)",
                         variable=self.use_lowercase, bg='white',
                         font=("Arial", 10))
        cb2.grid(row=1, column=0, sticky=W, padx=10, pady=2)
        
        cb3 = Checkbutton(checkbox_frame, text="✓ Digits (0-9)",
                         variable=self. use_digits, bg='white',
                         font=("Arial", 10))
        cb3.grid(row=0, column=1, sticky=W, padx=10, pady=2)
        
        cb4 = Checkbutton(checkbox_frame, text="✓ Symbols (! @#$%... )",
                         variable=self. use_symbols, bg='white',
                         font=("Arial", 10))
        cb4.grid(row=1, column=1, sticky=W, padx=10, pady=2)
        
        # Generate button
        gen_btn = Button(self.generator_frame, text="🎲 Generate Secure Password",
                        command=self.generate_password,
                        bg='#27ae60', fg='white',
                        font=("Arial", 11, "bold"),
                        padx=30, pady=10, relief=FLAT,
                        cursor='hand2')
        gen_btn.pack(pady=20)
        
        # Generated password display
        display_frame = Frame(self.generator_frame, bg='white')
        display_frame.pack(padx=20, pady=10, fill=X)
        
        Label(display_frame, text="Generated Password:",
              font=("Arial", 10, "bold"), bg='white').pack(anchor=W, pady=5)
        
        self. generated_password = Entry(display_frame, width=50,
                                        font=("Courier", 12, "bold"),
                                        relief=SOLID, borderwidth=1,
                                        justify=CENTER, fg='#2c3e50')
        self.generated_password. pack(pady=5, ipady=5)
        
        # Buttons frame
        btn_frame = Frame(self.generator_frame, bg='white')
        btn_frame.pack(pady=10)
        
        copy_btn = Button(btn_frame, text="📋 Copy to Clipboard",
                         command=self.copy_password,
                         bg='#3498db', fg='white',
                         font=("Arial", 10),
                         padx=15, pady=5, relief=FLAT,
                         cursor='hand2')
        copy_btn.pack(side=LEFT, padx=5)
        
        check_btn = Button(btn_frame, text="🔍 Check This Password",
                          command=self.check_generated_password,
                          bg='#9b59b6', fg='white',
                          font=("Arial", 10),
                          padx=15, pady=5, relief=FLAT,
                          cursor='hand2')
        check_btn.pack(side=LEFT, padx=5)
    
    def toggle_password(self):
        """Toggle password visibility"""
        if self.show_password_var.get():
            self.password_entry.config(show="")
        else:
            self.password_entry.config(show="*")
    
    def check_password(self):
        """
        Check password strength
        """
        password = self.password_entry.get()
        
        if not password:
            messagebox. showwarning("Input Required", 
                                  "Please enter a password to analyze!")
            return
        
        # Analyze the password
        analysis = analyze_password(password)
        
        if not analysis:
            return
        
        # Build result string
        result = f"""
╔══════════════════════════════════════════════════════════╗
║           PASSWORD STRENGTH ANALYSIS REPORT              ║
╚══════════════════════════════════════════════════════════╝

📊 PASSWORD INFORMATION:
   Length: {analysis['length']} characters
   Strength: {analysis['strength']}
   Score: {analysis['score']}/10

🔤 CHARACTER COMPOSITION:
   {'✓' if analysis['has_upper'] else '✗'} Uppercase letters (A-Z)
   {'✓' if analysis['has_lower'] else '✗'} Lowercase letters (a-z)
   {'✓' if analysis['has_digit'] else '✗'} Numbers (0-9)
   {'✓' if analysis['has_symbol'] else '✗'} Special symbols (!@#$%...)

⚠️  PATTERN DETECTION:
   {'✗ Sequential patterns found' if analysis['is_sequential'] else '✓ No sequential patterns'}
   {'✗ Repeated characters found' if analysis['is_repeated'] else '✓ No repeated characters'}
   {'✗ Common password detected!' if analysis['is_common'] else '✓ Not a common password'}

🔒 SECURITY METRICS:
   Entropy: {analysis['entropy']:.2f} bits
   Estimated crack time: {analysis['crack_time']}
   (Assuming 1 billion guesses/second)

💡 RECOMMENDATIONS:
"""
        
        # Add recommendations
        recommendations = []
        if analysis['length'] < 12:
            recommendations.append("   • Increase length to at least 12 characters")
        if not analysis['has_upper']:
            recommendations.append("   • Add uppercase letters (A-Z)")
        if not analysis['has_lower']: 
            recommendations.append("   • Add lowercase letters (a-z)")
        if not analysis['has_digit']:
            recommendations.append("   • Add numbers (0-9)")
        if not analysis['has_symbol']:
            recommendations.append("   • Add special symbols (!@#$%^&*)")
        if analysis['is_sequential']:
            recommendations.append("   • Avoid sequential patterns (abc, 123, etc.)")
        if analysis['is_repeated']:
            recommendations. append("   • Avoid repeated characters (aaa, 111, etc.)")
        if analysis['is_common']:
            recommendations.append("   • Avoid common passwords!")
        
        if recommendations:
            result += "\n". join(recommendations)
        else:
            result += "   ✓ Excellent!  This password meets all security criteria."
        
        result += "\n\n" + "═" * 60
        
        # Display results
        self.result_text. config(state=NORMAL)
        self.result_text.delete(1.0, END)
        self.result_text.insert(1.0, result)
        
        # Highlight strength with color
        self.result_text.tag_add("strength", "5.13", "5.50")
        self.result_text.tag_config("strength", 
                                   foreground=analysis['color'],
                                   font=("Arial", 11, "bold"))
        
        self.result_text.config(state=DISABLED)
    
    def generate_password(self):
        """Generate a secure random password"""
        length = self.length_var.get()
        
        # Build character pool
        char_pool = ""
        if self.use_uppercase.get():
            char_pool += string.ascii_uppercase
        if self.use_lowercase.get():
            char_pool += string.ascii_lowercase
        if self.use_digits.get():
            char_pool += string.digits
        if self.use_symbols.get():
            char_pool += string.punctuation
        
        if not char_pool:
            messagebox.showerror("Error", 
                                "Please select at least one character type!")
            return
        
        if length < 4:
            messagebox.showwarning("Warning",
                                  "Password length should be at least 4 characters!")
            return
        
        # Generate password using secrets (cryptographically secure)
        password = ''.join(secrets.choice(char_pool) for _ in range(length))
        
        # Display generated password
        self.generated_password.delete(0, END)
        self.generated_password.insert(0, password)
        
        # Optional: Show strength notification
        analysis = analyze_password(password)
        messagebox.showinfo("Password Generated",
                           f"Generated a {analysis['strength']} password!\n"
                           f"Entropy: {analysis['entropy']:.0f} bits\n"
                           f"Crack time: {analysis['crack_time']}")
    
    def copy_password(self):
        """Copy generated password to clipboard"""
        password = self.generated_password.get()
        
        if not password:
            messagebox. showwarning("No Password",
                                  "Please generate a password first!")
            return
        
        self.root.clipboard_clear()
        self.root.clipboard_append(password)
        messagebox.showinfo("Success", "Password copied to clipboard!  📋")
    
    def check_generated_password(self):
        """Switch to checker tab and analyze generated password"""
        password = self.generated_password.get()
        
        if not password:
            messagebox.showwarning("No Password",
                                  "Please generate a password first!")
            return
        
        # Switch to checker tab
        self. notebook.select(0)
        
        # Set password and analyze
        self.password_entry.delete(0, END)
        self.password_entry.insert(0, password)
        self.check_password()


def main():
    """Main function to run the application"""
    root = Tk()
    app = PasswordToolApp(root)
    
    # Center window on screen
    root.update_idletasks()
    width = root.winfo_width()
    height = root.winfo_height()
    x = (root.winfo_screenwidth() // 2) - (width // 2)
    y = (root.winfo_screenheight() // 2) - (height // 2)
    root.geometry(f'{width}x{height}+{x}+{y}')
    
    root.mainloop()


if __name__ == "__main__":
    main()