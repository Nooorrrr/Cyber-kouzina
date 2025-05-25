import customtkinter as ctk
from tkinter import messagebox
import os
from algorithms.cipher_factory import CipherFactory

class CyberKouzinaApp:
    def __init__(self):
        self.app = ctk.CTk()
        self.app.title("Cyber Kouzina")
        self.app.geometry("800x600")
        
        # Configure grid
        self.app.grid_columnconfigure(0, weight=1)
        self.app.grid_rowconfigure(0, weight=1)
        
        # Create main frame
        self.main_frame = ctk.CTkFrame(self.app)
        self.main_frame.grid(row=0, column=0, padx=20, pady=20, sticky="nsew")
        self.main_frame.grid_columnconfigure(0, weight=1)
        self.main_frame.grid_rowconfigure((0, 1, 2), weight=1)
        
        # Create buttons
        self.encryption_btn = ctk.CTkButton(
            self.main_frame,
            text="Encryption",
            command=self.open_encryption_window,
            height=40
        )
        self.encryption_btn.grid(row=0, column=0, padx=20, pady=20, sticky="ew")
        
        self.cryptanalysis_btn = ctk.CTkButton(
            self.main_frame,
            text="Cryptanalysis",
            command=self.open_cryptanalysis_window,
            height=40
        )
        self.cryptanalysis_btn.grid(row=1, column=0, padx=20, pady=20, sticky="ew")
        
        self.signature_btn = ctk.CTkButton(
            self.main_frame,
            text="Signature and Hashes",
            command=self.open_signature_window,
            height=40
        )
        self.signature_btn.grid(row=2, column=0, padx=20, pady=20, sticky="ew")

    def open_encryption_window(self):
        EncryptionWindow(self.app)
    
    def open_cryptanalysis_window(self):
        CryptanalysisWindow(self.app)
    
    def open_signature_window(self):
        SignatureWindow(self.app)

    def run(self):
        self.app.mainloop()

class EncryptionWindow:
    def __init__(self, parent):
        self.window = ctk.CTkToplevel(parent)
        self.window.title("Encryption")
        self.window.geometry("1000x700")
        
        # Create tabview
        self.tabview = ctk.CTkTabview(self.window)
        self.tabview.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Create tabs
        self.classic_tab = self.tabview.add("Classic Ciphers")
        self.symmetric_tab = self.tabview.add("Symmetric Ciphers")
        self.asymmetric_tab = self.tabview.add("Asymmetric Ciphers")
        
        # Initialize each tab
        self.setup_classic_tab()
        self.setup_symmetric_tab()
        self.setup_asymmetric_tab()
        
        # Store current cipher
        self.current_cipher = None
        self.parameter_entries = {}

    def setup_classic_tab(self):
        # Create sidebar frame
        sidebar = ctk.CTkFrame(self.classic_tab)
        sidebar.pack(side="left", fill="y", padx=10, pady=10)
        
        # Create buttons
        ciphers = CipherFactory.get_ciphers_by_type('classic')
        for cipher in ciphers:
            btn = ctk.CTkButton(
                sidebar,
                text=cipher.title(),
                command=lambda c=cipher: self.show_cipher_interface(c, 'classic')
            )
            btn.pack(padx=10, pady=5, fill="x")
        
        # Create main content frame
        self.classic_content = ctk.CTkFrame(self.classic_tab)
        self.classic_content.pack(side="right", fill="both", expand=True, padx=10, pady=10)

    def setup_symmetric_tab(self):
        # Create sidebar frame
        sidebar = ctk.CTkFrame(self.symmetric_tab)
        sidebar.pack(side="left", fill="y", padx=10, pady=10)
        
        # Create buttons
        ciphers = CipherFactory.get_ciphers_by_type('symmetric')
        for cipher in ciphers:
            btn = ctk.CTkButton(
                sidebar,
                text=cipher.upper(),
                command=lambda c=cipher: self.show_cipher_interface(c, 'symmetric')
            )
            btn.pack(padx=10, pady=5, fill="x")
        
        # Create main content frame
        self.symmetric_content = ctk.CTkFrame(self.symmetric_tab)
        self.symmetric_content.pack(side="right", fill="both", expand=True, padx=10, pady=10)

    def setup_asymmetric_tab(self):
        # Create sidebar frame
        sidebar = ctk.CTkFrame(self.asymmetric_tab)
        sidebar.pack(side="left", fill="y", padx=10, pady=10)
        
        # Create buttons
        ciphers = CipherFactory.get_ciphers_by_type('asymmetric')
        for cipher in ciphers:
            btn = ctk.CTkButton(
                sidebar,
                text=cipher.title(),
                command=lambda c=cipher: self.show_cipher_interface(c, 'asymmetric')
            )
            btn.pack(padx=10, pady=5, fill="x")
        
        # Create main content frame
        self.asymmetric_content = ctk.CTkFrame(self.asymmetric_tab)
        self.asymmetric_content.pack(side="right", fill="both", expand=True, padx=10, pady=10)

    def show_cipher_interface(self, cipher_name: str, cipher_type: str):
        # Clear previous content
        if cipher_type == 'classic':
            content_frame = self.classic_content
        elif cipher_type == 'symmetric':
            content_frame = self.symmetric_content
        else:
            content_frame = self.asymmetric_content
            
        for widget in content_frame.winfo_children():
            widget.destroy()
        
        # Get cipher instance
        self.current_cipher = CipherFactory.get_cipher(cipher_name)
        
        # Create input fields
        input_label = ctk.CTkLabel(content_frame, text="Input Text:")
        input_label.pack(padx=10, pady=5)
        
        self.input_text = ctk.CTkTextbox(content_frame, height=100)
        self.input_text.pack(padx=10, pady=5, fill="x")
        
        # Create parameter fields
        params_frame = ctk.CTkFrame(content_frame)
        params_frame.pack(padx=10, pady=10, fill="x")
        
        self.parameter_entries.clear()
        
        # Add parameter input fields based on cipher type
        if cipher_type == 'classic':
            if cipher_name == 'base64':
                # Base64 doesn't need parameters
                params_label = ctk.CTkLabel(params_frame, text="Base64 encoding/decoding (no parameters needed)")
                params_label.pack(padx=10, pady=5)
            elif cipher_name == 'caesar':
                self._add_parameter_field(params_frame, 'shift', 'Shift Value (0-25):')
            elif cipher_name == 'xor':
                self._add_parameter_field(params_frame, 'key', 'Key:')
            elif cipher_name == 'vigenere':
                self._add_parameter_field(params_frame, 'key', 'Key (letters only):')
            elif cipher_name == 'affine':
                self._add_parameter_field(params_frame, 'a', 'Multiplier (coprime with 26):')
                self._add_parameter_field(params_frame, 'b', 'Shift Value (0-25):')
        
        elif cipher_type == 'symmetric':
            self._add_parameter_field(params_frame, 'key', 'Key (Base64):')
            if cipher_name != 'rc4':  # RC4 doesn't use IV
                self._add_parameter_field(params_frame, 'iv', 'IV (Base64):')
        
        elif cipher_type == 'asymmetric':
            if cipher_name == 'rsa':
                self._add_parameter_field(params_frame, 'public_key', 'Public Key (Base64):')
                self._add_parameter_field(params_frame, 'private_key', 'Private Key (Base64):')
            elif cipher_name == 'diffie-hellman':
                self._add_parameter_field(params_frame, 'public_key', 'Public Key (Base64):')
                self._add_parameter_field(params_frame, 'private_key', 'Private Key (Base64):')
            elif cipher_name == 'elgamal':
                self._add_parameter_field(params_frame, 'p', 'Prime p:')
                self._add_parameter_field(params_frame, 'g', 'Generator g:')
                self._add_parameter_field(params_frame, 'public_key', 'Public Key y:')
                self._add_parameter_field(params_frame, 'private_key', 'Private Key x:')
        
        # Add generate parameters button (hide for Base64)
        if cipher_name != 'base64':
            generate_btn = ctk.CTkButton(
                params_frame,
                text="Generate Parameters",
                command=self.generate_parameters
            )
            generate_btn.pack(padx=10, pady=5)
        
        # Add encrypt/decrypt buttons
        button_frame = ctk.CTkFrame(content_frame)
        button_frame.pack(padx=10, pady=10)
        
        encrypt_btn = ctk.CTkButton(
            button_frame,
            text="Encrypt",
            command=self.encrypt
        )
        encrypt_btn.pack(side="left", padx=5)
        
        decrypt_btn = ctk.CTkButton(
            button_frame,
            text="Decrypt",
            command=self.decrypt
        )
        decrypt_btn.pack(side="left", padx=5)
        
        # Add result field
        result_label = ctk.CTkLabel(content_frame, text="Result:")
        result_label.pack(padx=10, pady=5)
        
        self.result_text = ctk.CTkTextbox(content_frame, height=100)
        self.result_text.pack(padx=10, pady=5, fill="x")

    def _add_parameter_field(self, parent, name: str, label: str):
        """Helper method to add a parameter input field"""
        frame = ctk.CTkFrame(parent)
        frame.pack(padx=10, pady=5, fill="x")
        
        label = ctk.CTkLabel(frame, text=label)
        label.pack(side="left", padx=5)
        
        entry = ctk.CTkEntry(frame)
        entry.pack(side="left", padx=5, fill="x", expand=True)
        
        self.parameter_entries[name] = entry

    def generate_parameters(self):
        if not self.current_cipher:
            return
            
        # Generate parameters
        params = self.current_cipher.generate_parameters()
        
        # Clear previous parameter fields
        for widget in self.parameter_entries.values():
            widget.destroy()
        self.parameter_entries.clear()
        
        # Create new parameter fields
        params_frame = self.result_text.master
        for name, value in params.items():
            frame = ctk.CTkFrame(params_frame)
            frame.pack(padx=10, pady=5, fill="x")
            
            label = ctk.CTkLabel(frame, text=f"{name.title()}:")
            label.pack(side="left", padx=5)
            
            entry = ctk.CTkEntry(frame)
            entry.insert(0, str(value))
            entry.pack(side="left", padx=5, fill="x", expand=True)
            
            self.parameter_entries[name] = entry

    def get_parameters(self):
        return {name: entry.get() for name, entry in self.parameter_entries.items()}

    def encrypt(self):
        if not self.current_cipher:
            return
            
        try:
            # Get input text and parameters
            text = self.input_text.get("1.0", "end-1c")
            params = self.get_parameters()
            
            # Encrypt
            result = self.current_cipher.encrypt(text, **params)
            
            # Show result
            self.result_text.delete("1.0", "end")
            self.result_text.insert("1.0", result)
            
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def decrypt(self):
        if not self.current_cipher:
            return
            
        try:
            # Get input text and parameters
            text = self.input_text.get("1.0", "end-1c")
            params = self.get_parameters()
            
            # Decrypt
            result = self.current_cipher.decrypt(text, **params)
            
            # Show result
            self.result_text.delete("1.0", "end")
            self.result_text.insert("1.0", result)
            
        except Exception as e:
            messagebox.showerror("Error", str(e))

class CryptanalysisWindow:
    def __init__(self, parent):
        self.window = ctk.CTkToplevel(parent)
        self.window.title("Cryptanalysis")
        self.window.geometry("1000x700")
        
        # Main layout
        self.main_frame = ctk.CTkFrame(self.window)
        self.main_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Left panel for ciphertext and settings
        self.left_panel = ctk.CTkFrame(self.main_frame)
        self.left_panel.pack(side="left", fill="both", expand=True, padx=5)
        
        # Ciphertext input
        self.ciphertext_label = ctk.CTkLabel(self.left_panel, text="Ciphertext:")
        self.ciphertext_label.pack(padx=10, pady=5)
        
        self.ciphertext_input = ctk.CTkTextbox(self.left_panel, height=200)
        self.ciphertext_input.pack(padx=10, pady=5, fill="x")
        
        # Analysis method selection
        self.method_frame = ctk.CTkFrame(self.left_panel)
        self.method_frame.pack(fill="x", padx=10, pady=10)
        
        self.method_label = ctk.CTkLabel(self.method_frame, text="Analysis Method:")
        self.method_label.pack(side="left", padx=5)
        
        self.method_var = ctk.StringVar(value="Frequency Analysis")
        self.method_menu = ctk.CTkOptionMenu(
            self.method_frame,
            values=["Frequency Analysis", "Kasiski Test"],
            variable=self.method_var
        )
        self.method_menu.pack(side="left", padx=5)
        
        # Analysis button
        self.analyze_btn = ctk.CTkButton(
            self.left_panel,
            text="Analyze",
            command=self.analyze_text
        )
        self.analyze_btn.pack(pady=10)
        
        # Right panel for results
        self.right_panel = ctk.CTkFrame(self.main_frame)
        self.right_panel.pack(side="right", fill="both", expand=True, padx=5)
        
        # Results area
        self.results_label = ctk.CTkLabel(self.right_panel, text="Analysis Results:")
        self.results_label.pack(padx=10, pady=5)
        
        self.results_text = ctk.CTkTextbox(self.right_panel, height=400)
        self.results_text.pack(padx=10, pady=5, fill="both", expand=True)

    def analyze_text(self):
        # Get ciphertext
        ciphertext = self.ciphertext_input.get("1.0", "end-1c")
        if not ciphertext:
            messagebox.showwarning("Warning", "Please enter ciphertext to analyze.")
            return
        
        # Create appropriate analyzer
        if self.method_var.get() == "Frequency Analysis":
            from algorithms.cryptanalysis.frequency_analysis import FrequencyAnalysis
            analyzer = FrequencyAnalysis()
        else:  # Kasiski Test
            from algorithms.cryptanalysis.kasiski_test import KasiskiTest
            analyzer = KasiskiTest()
        
        try:
            # Perform analysis
            results = analyzer.analyze(ciphertext)
            
            # Clear previous results
            self.results_text.delete("1.0", "end")
            
            # Format and display results
            if self.method_var.get() == "Frequency Analysis":
                self._display_frequency_analysis(results)
            else:
                self._display_kasiski_results(results)
                
        except Exception as e:
            messagebox.showerror("Error", str(e))
    
    def _display_frequency_analysis(self, results: dict):
        # Display letter frequencies
        self.results_text.insert("end", "Letter Frequencies:\n")
        for char, freq in sorted(results['frequencies'].items(), key=lambda x: x[1], reverse=True):
            self.results_text.insert("end", f"{char}: {freq:.2f}%\n")
        
        self.results_text.insert("end", "\nMost Common Digrams:\n")
        for digram, freq in results['digrams'].items():
            self.results_text.insert("end", f"{digram}: {freq:.2f}%\n")
        
        self.results_text.insert("end", "\nLikely Substitutions:\n")
        for cipher_char, details in results['likely_substitutions'].items():
            if details['confidence'] > 0.5:  # Show only high confidence matches
                self.results_text.insert(
                    "end",
                    f"{cipher_char} → {details['likely_plain']} "
                    f"(confidence: {details['confidence']:.2f})\n"
                )
        
        self.results_text.insert("end", "\nPartial Decryption:\n")
        self.results_text.insert("end", results['partial_decrypt'])
        
        self.results_text.insert(
            "end",
            f"\n\nOverall Analysis Confidence: {results['confidence']:.2f}"
        )
    
    def _display_kasiski_results(self, results: dict):
        self.results_text.insert("end", "Kasiski Test Results:\n\n")
        self.results_text.insert("end", "Possible Key Lengths and Keys:\n")
        
        for key_length, details in results.items():
            self.results_text.insert(
                "end",
                f"Key Length {key_length}:\n"
                f"Suggested Key: {details['key']}\n"
                f"Confidence: {details['confidence']:.2f}\n\n"
            )

class SignatureWindow:
    def __init__(self, parent):
        self.window = ctk.CTkToplevel(parent)
        self.window.title("Signature and Hashes")
        self.window.geometry("1000x700")
        
        # Create tabview
        self.tabview = ctk.CTkTabview(self.window)
        self.tabview.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Create tabs
        self.hash_tab = self.tabview.add("Hash Functions")
        self.signature_tab = self.tabview.add("Digital Signatures")
        
        # Initialize tabs
        self.setup_hash_tab()
        self.setup_signature_tab()

    def setup_hash_tab(self):
        # Input frame
        input_frame = ctk.CTkFrame(self.hash_tab)
        input_frame.pack(fill="x", padx=10, pady=5)
        
        # Input text
        input_label = ctk.CTkLabel(input_frame, text="Input Text:")
        input_label.pack(padx=10, pady=5)
        
        self.hash_input = ctk.CTkTextbox(input_frame, height=100)
        self.hash_input.pack(padx=10, pady=5, fill="x")
        
        # Hash type selection
        type_frame = ctk.CTkFrame(self.hash_tab)
        type_frame.pack(fill="x", padx=10, pady=5)
        
        type_label = ctk.CTkLabel(type_frame, text="Hash Function:")
        type_label.pack(side="left", padx=5)
        
        self.hash_type = ctk.StringVar(value="SHA-256")
        type_menu = ctk.CTkOptionMenu(
            type_frame,
            values=["SHA-256", "SHA-3", "BLAKE2"],
            variable=self.hash_type
        )
        type_menu.pack(side="left", padx=5)
        
        # Calculate button
        calculate_btn = ctk.CTkButton(
            self.hash_tab,
            text="Calculate Hash",
            command=self.calculate_hash
        )
        calculate_btn.pack(pady=10)
        
        # Results
        result_frame = ctk.CTkFrame(self.hash_tab)
        result_frame.pack(fill="x", padx=10, pady=5)
        
        result_label = ctk.CTkLabel(result_frame, text="Hash Value:")
        result_label.pack(padx=10, pady=5)
        
        self.hash_result = ctk.CTkTextbox(result_frame, height=100)
        self.hash_result.pack(padx=10, pady=5, fill="x")

    def setup_signature_tab(self):
        # Signature method selection
        method_frame = ctk.CTkFrame(self.signature_tab)
        method_frame.pack(fill="x", padx=10, pady=5)
        
        method_label = ctk.CTkLabel(method_frame, text="Algorithm:")
        method_label.pack(side="left", padx=5)
        
        self.sig_method = ctk.StringVar(value="RSA")
        method_menu = ctk.CTkOptionMenu(
            method_frame,
            values=["RSA", "ElGamal"],
            variable=self.sig_method,
            command=self.update_signature_interface
        )
        method_menu.pack(side="left", padx=5)
        
        # Message input
        input_label = ctk.CTkLabel(self.signature_tab, text="Message:")
        input_label.pack(padx=10, pady=5)
        
        self.sig_input = ctk.CTkTextbox(self.signature_tab, height=100)
        self.sig_input.pack(padx=10, pady=5, fill="x")
        
        # Key frame
        self.key_frame = ctk.CTkFrame(self.signature_tab)
        self.key_frame.pack(fill="x", padx=10, pady=5)
        
        # Will be populated by update_signature_interface
        
        # Generate key pair button
        self.generate_btn = ctk.CTkButton(
            self.signature_tab,
            text="Generate Key Pair",
            command=self.generate_key_pair
        )
        self.generate_btn.pack(pady=5)
        
        # Sign/Verify buttons
        button_frame = ctk.CTkFrame(self.signature_tab)
        button_frame.pack(pady=10)
        
        sign_btn = ctk.CTkButton(
            button_frame,
            text="Sign",
            command=self.sign_message
        )
        sign_btn.pack(side="left", padx=5)
        
        verify_btn = ctk.CTkButton(
            button_frame,
            text="Verify",
            command=self.verify_signature
        )
        verify_btn.pack(side="left", padx=5)
        
        # Signature/Verification result
        result_label = ctk.CTkLabel(self.signature_tab, text="Signature/Verification Result:")
        result_label.pack(padx=10, pady=5)
        
        self.sig_result = ctk.CTkTextbox(self.signature_tab, height=100)
        self.sig_result.pack(padx=10, pady=5, fill="x")
        
        # Initialize the interface
        self.update_signature_interface(self.sig_method.get())

    def update_signature_interface(self, method):
        # Clear previous key fields
        for widget in self.key_frame.winfo_children():
            widget.destroy()
        
        if method == "RSA":
            # RSA keys (Base64 format)
            private_label = ctk.CTkLabel(self.key_frame, text="Private Key (Base64):")
            private_label.pack(padx=10, pady=5)
            
            self.private_key = ctk.CTkTextbox(self.key_frame, height=50)
            self.private_key.pack(padx=10, pady=5, fill="x")
            
            public_label = ctk.CTkLabel(self.key_frame, text="Public Key (Base64):")
            public_label.pack(padx=10, pady=5)
            
            self.public_key = ctk.CTkTextbox(self.key_frame, height=50)
            self.public_key.pack(padx=10, pady=5, fill="x")
            
        else:  # ElGamal
            # ElGamal parameters
            for param in ['p', 'g', 'private_key', 'public_key']:
                label = ctk.CTkLabel(self.key_frame, 
                                   text=f"{param.replace('_', ' ').title()}:")
                label.pack(padx=10, pady=2)
                
                entry = ctk.CTkEntry(self.key_frame)
                entry.pack(padx=10, pady=2, fill="x")
                setattr(self, param, entry)

    def calculate_hash(self):
        from Crypto.Hash import SHA256, SHA3_256, BLAKE2b
        
        text = self.hash_input.get("1.0", "end-1c")
        if not text:
            messagebox.showwarning("Warning", "Please enter text to hash.")
            return
        
        # Convert text to bytes
        data = text.encode('utf-8')
        
        # Calculate hash based on selected function
        if self.hash_type.get() == "SHA-256":
            hash_obj = SHA256.new(data)
        elif self.hash_type.get() == "SHA-3":
            hash_obj = SHA3_256.new(data)
        else:  # BLAKE2
            hash_obj = BLAKE2b.new(data=data)
        
        # Display result
        self.hash_result.delete("1.0", "end")
        self.hash_result.insert("1.0", hash_obj.hexdigest())

    def generate_key_pair(self):
        if self.sig_method.get() == "RSA":
            # Generate RSA key pair
            from algorithms.asymmetric.rsa import RSACipher
            cipher = RSACipher()
            keys = cipher.generate_parameters()
            
            # Display keys
            self.private_key.delete("1.0", "end")
            self.private_key.insert("1.0", keys['private_key'])
            
            self.public_key.delete("1.0", "end")
            self.public_key.insert("1.0", keys['public_key'])
            
        else:  # ElGamal
            # Generate ElGamal parameters
            from algorithms.asymmetric.elgamal import ElGamalCipher
            cipher = ElGamalCipher()
            params = cipher.generate_parameters()
            
            # Display parameters
            for param in ['p', 'g', 'private_key', 'public_key']:
                widget = getattr(self, param)
                widget.delete(0, "end")
                widget.insert(0, params[param])

    def sign_message(self):
        try:
            message = self.sig_input.get("1.0", "end-1c")
            if not message:
                raise ValueError("Please enter a message to sign.")

            if self.sig_method.get() == "RSA":
                from algorithms.asymmetric.rsa import RSACipher
                cipher = RSACipher()
                
                private_key = self.private_key.get("1.0", "end-1c")
                signature = cipher.sign(message, private_key=private_key)
                
            else:  # ElGamal
                from algorithms.asymmetric.elgamal import ElGamalCipher
                cipher = ElGamalCipher()
                
                # Get parameters
                params = {
                    'p': self.p.get(),
                    'g': self.g.get(),
                    'private_key': self.private_key.get(),
                    'public_key': self.public_key.get()
                }
                
                signature = cipher.sign(message, **params)
            
            # Display signature
            self.sig_result.delete("1.0", "end")
            self.sig_result.insert("1.0", signature)
            
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def verify_signature(self):
        try:
            message = self.sig_input.get("1.0", "end-1c")
            signature = self.sig_result.get("1.0", "end-1c")
            
            if not message or not signature:
                raise ValueError("Please provide both message and signature.")

            if self.sig_method.get() == "RSA":
                from algorithms.asymmetric.rsa import RSACipher
                cipher = RSACipher()
                
                public_key = self.public_key.get("1.0", "end-1c")
                valid = cipher.verify(message, signature, public_key=public_key)
                
            else:  # ElGamal
                from algorithms.asymmetric.elgamal import ElGamalCipher
                cipher = ElGamalCipher()
                
                # Get parameters
                params = {
                    'p': self.p.get(),
                    'g': self.g.get(),
                    'public_key': self.public_key.get()
                }
                
                valid = cipher.verify(message, signature, **params)
            
            # Show verification result
            if valid:
                messagebox.showinfo("Success", "Signature is valid!")
            else:
                messagebox.showerror("Error", "Invalid signature!")
            
        except Exception as e:
            messagebox.showerror("Error", str(e))

if __name__ == "__main__":
    app = CyberKouzinaApp()
    app.run() 