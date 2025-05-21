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
        self.window.geometry("800x600")
        # Implementation will be added later

class SignatureWindow:
    def __init__(self, parent):
        self.window = ctk.CTkToplevel(parent)
        self.window.title("Signature and Hashes")
        self.window.geometry("800x600")
        # Implementation will be added later

if __name__ == "__main__":
    app = CyberKouzinaApp()
    app.run() 