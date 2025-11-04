# GnuPG Integration Guide

This document describes how to integrate GnuPG (GNU Privacy Guard) functionality with GNU Radio Linux Crypto module, including PIN handling for hardware security tokens and smart cards.

## Overview

The gr-linux-crypto module provides **limited GnuPG integration** via subprocess calls to the `gpg` command-line tool. This integration is primarily used for:
- Session key encryption/decryption
- Digital signing and verification
- Key management operations

**Important Limitations:**
- Uses subprocess calls to `gpg` CLI, not native library integration
- PIN handling relies on GnuPG agent and pinentry programs
- No direct GNU Radio block implementation (currently Python utilities only)
- Requires proper GnuPG setup and configuration

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [GnuPG Setup](#gnupg-setup)
3. [PIN Handling](#pin-handling)
4. [Using GnuPG in GNU Radio](#using-gnupg-in-gnu-radio)
5. [Integration Patterns](#integration-patterns)
6. [Examples](#examples)
7. [Troubleshooting](#troubleshooting)
8. [Future Improvements](#future-improvements)
9. [Legal and Appropriate Uses for Amateur Radio](#legal-and-appropriate-uses-for-amateur-radio)
10. [References](#references)
11. [See Also](#see-also)

## Prerequisites

### Required Software

```bash
# Install GnuPG and agent
sudo apt-get install gnupg2 gnupg-agent pinentry-gtk2 pinentry-qt

# Verify installation
gpg --version
```

### Hardware Security Tokens (Optional)

For smart cards and hardware tokens (e.g., Nitrokey, YubiKey):

```bash
# Install smart card support
sudo apt-get install scdaemon pcscd

# Enable smart card support in GnuPG
echo "reader-port Yubico" >> ~/.gnupg/scdaemon.conf
```

## GnuPG Setup

### 1. Generate or Import Keys

**Generate a new key pair:**
```bash
gpg --full-generate-key
# Follow prompts to select key type, size, expiration
```

**Import existing key:**
```bash
gpg --import public_key.asc
gpg --import private_key.asc
```

**List your keys:**
```bash
gpg --list-secret-keys
gpg --list-keys
```

### 2. Configure GnuPG Agent

Edit `~/.gnupg/gpg-agent.conf`:
```
# Pinentry program (GUI for PIN entry)
pinentry-program /usr/bin/pinentry-gtk-2

# Cache PINs for specified time (in seconds)
# Default: 3600 (1 hour)
default-cache-ttl 3600

# Maximum cache time (in seconds)
# Default: 7200 (2 hours)
max-cache-ttl 7200

# Enable SSH agent emulation (optional)
enable-ssh-support
```

**For Battery-Powered Devices:**

For devices that may be turned on/off frequently (e.g., battery-powered SDR devices), you can configure longer timeouts so you only need to enter the PIN when the device is first powered on:

```
# Cache PIN for a week (7 days * 24 hours * 3600 seconds = 604800)
default-cache-ttl 604800

# Maximum cache time for a month (30 days * 24 hours * 3600 seconds = 2592000)
max-cache-ttl 2592000
```

**Timeout Configuration:**
- `default-cache-ttl`: Time before PIN is required again after last use
- `max-cache-ttl`: Maximum time PIN can be cached (even if not used)
- Values are in seconds
- Common values:
  - 1 hour: `3600`
  - 1 day: `86400`
  - 1 week: `604800`
  - 1 month (30 days): `2592000`

**Security Note:** Longer timeouts reduce security but improve usability. The PIN will still be required when the device is first powered on or after the timeout expires. Choose a timeout that balances security and convenience for your use case.

Reload the agent after making changes:
```bash
gpg-connect-agent reloadagent /bye
```

### 3. Verify Agent is Running

```bash
gpg-connect-agent --version
# Should show agent version
```

Test PIN entry:
```bash
gpg --card-status
# If using smart card, will prompt for PIN
```

## PIN Handling

### Understanding PIN Entry in GnuPG

GnuPG uses the **GnuPG agent** (`gpg-agent`) to handle PIN entry securely. When an operation requires a PIN (e.g., smart card access, encrypted private key), the agent launches a pinentry program to prompt the user.

### PIN Entry Flow

```
GNU Radio Application
    ↓
gpg subprocess call
    ↓
GnuPG (gpg binary)
    ↓
GnuPG Agent (gpg-agent)
    ↓
Pinentry Program (GUI/CLI dialog)
    ↓
User enters PIN
    ↓
PIN returned to GnuPG Agent
    ↓
Operation completes
```

### Available Pinentry Programs

| Program | Type | Use Case |
|---------|------|----------|
| `pinentry-gtk-2` | GUI (GTK2) | Desktop applications |
| `pinentry-qt` | GUI (Qt) | Qt-based applications |
| `pinentry-gnome3` | GUI (GNOME) | GNOME desktop |
| `pinentry-curses` | TUI | Terminal applications |
| `pinentry-tty` | CLI | Headless servers |

### Configuration for GNU Radio

**For GUI applications (GNU Radio Companion):**
```bash
# ~/.gnupg/gpg-agent.conf
pinentry-program /usr/bin/pinentry-gtk-2
```

**For headless/server applications:**
```bash
# ~/.gnupg/gpg-agent.conf
pinentry-program /usr/bin/pinentry-curses
# OR for automated systems (not recommended for production):
# pinentry-program /usr/bin/pinentry-tty
```

**Setting PIN via environment variable (unsafe, testing only):**
```bash
# Not recommended - PIN visible in process list
export GPG_TTY=$(tty)
echo "your-pin" | gpg --batch --pinentry-mode loopback --passphrase-fd 0 --decrypt file.gpg
```

### Pre-authenticating PIN (Session-based)

To avoid repeated PIN prompts during a session:

```bash
# Pre-authenticate (PIN cached for session)
gpg-connect-agent "SCD CHECKPIN <keygrip>" /bye

# Or interactively unlock
gpg --card-edit
> admin
> passwd
# Enter PIN and Admin PIN when prompted
```

## Using GnuPG in GNU Radio

### Current Implementation

The module provides GnuPG integration via the `M17SessionKeyExchange` class in `python/m17_frame.py`. This class uses subprocess calls to the `gpg` command.

### Basic Usage Example

```python
from gr_linux_crypto.python.m17_frame import M17SessionKeyExchange

# Generate session key
session_key = M17SessionKeyExchange.generate_session_key()

# Encrypt session key for recipient
# Requires recipient's public key in GnuPG keyring
encrypted_key = M17SessionKeyExchange.encrypt_key_for_recipient(
    session_key, 
    recipient_key_id="0xABCD1234"  # GnuPG key ID or fingerprint
)

# Sign data with your key
# Will prompt for PIN if using hardware token
signed_data = M17SessionKeyExchange.sign_key_offer(
    session_key,
    sender_key_id="0x5678EF90"
)

# Verify signature
is_valid = M17SessionKeyExchange.verify_key_offer_signature(signed_data)

# Decrypt session key
# Will prompt for PIN if private key is protected
decrypted_key = M17SessionKeyExchange.decrypt_key(encrypted_key)
```

### Integration with GNU Radio Flowgraphs

**Python block wrapper example:**
```python
#!/usr/bin/env python3
from gnuradio import gr
from gr_linux_crypto.python.m17_frame import M17SessionKeyExchange

class GnuPGEncryptBlock(gr.sync_block):
    """GNU Radio block for GnuPG encryption."""
    
    def __init__(self, recipient_key_id):
        gr.sync_block.__init__(
            self,
            name="GnuPG Encrypt",
            in_sig=[np.uint8],
            out_sig=[np.uint8]
        )
        self.recipient_key_id = recipient_key_id
        self.session_key = M17SessionKeyExchange.generate_session_key()
    
    def work(self, input_items, output_items):
        # Encrypt session key
        encrypted_key = M17SessionKeyExchange.encrypt_key_for_recipient(
            self.session_key,
            self.recipient_key_id
        )
        
        # Use session key to encrypt data stream
        # (Implementation depends on your encryption scheme)
        
        return len(output_items[0])
```

## Integration Patterns

### Pattern 1: Session Key Exchange

Use GnuPG to encrypt/decrypt session keys, then use faster symmetric encryption for data:

```python
# 1. Generate symmetric session key
session_key = secrets.token_bytes(32)

# 2. Encrypt session key with GnuPG (asymmetric, for recipient)
encrypted_session_key = M17SessionKeyExchange.encrypt_key_for_recipient(
    session_key,
    recipient_key_id
)

# 3. Use session key with AES (symmetric, fast)
from gr_linux_crypto.python.linux_crypto import encrypt
ciphertext, iv, auth_tag = encrypt('aes-256', session_key, data, auth='gcm')

# 4. Send: encrypted_session_key + ciphertext
```

### Pattern 2: Signature Verification

Verify authenticity of received data:

```python
# On sender side
signature = M17SessionKeyExchange.sign_key_offer(data, sender_key_id)

# On receiver side
is_valid = M17SessionKeyExchange.verify_key_offer_signature(signature)
if not is_valid:
    raise ValueError("Signature verification failed")
```

### Pattern 3: Hybrid Encryption

Combine GnuPG with kernel crypto for performance:

```python
# 1. GnuPG for key exchange (slow but secure)
shared_secret = M17SessionKeyExchange.decrypt_key(encrypted_key)

# 2. Store key in kernel keyring (secure storage)
from gr_linux_crypto.python.keyring_helper import KeyringHelper
helper = KeyringHelper()
key_id = helper.add_key('user', 'session_key', shared_secret)

# 3. Use kernel crypto API for fast encryption
from gnuradio import linux_crypto
encryptor = linux_crypto.kernel_crypto_aes(
    key=shared_secret,
    iv=initialization_vector,
    mode='gcm',
    encrypt=True
)
```

## Examples

### Example 1: Basic Encryption/Decryption

```python
#!/usr/bin/env python3
"""Basic GnuPG encryption/decryption example."""

from gr_linux_crypto.python.m17_frame import M17SessionKeyExchange

# Setup: Ensure keys are in GnuPG keyring
# gpg --list-keys
# gpg --list-secret-keys

recipient_key_id = "alice@example.com"  # Or key ID: 0x12345678

# Generate and encrypt session key
session_key = M17SessionKeyExchange.generate_session_key()
print(f"Generated session key: {session_key.hex()}")

encrypted = M17SessionKeyExchange.encrypt_key_for_recipient(
    session_key,
    recipient_key_id
)

if encrypted:
    print(f"Encrypted session key (ASCII-armored):")
    print(encrypted.decode())
    
    # Decrypt (will prompt for PIN if needed)
    decrypted = M17SessionKeyExchange.decrypt_key(encrypted)
    if decrypted:
        print(f"Decrypted session key: {decrypted.hex()}")
        assert decrypted == session_key
else:
    print("Encryption failed - check recipient key ID")
```

### Example 2: Signing with Hardware Token

```python
#!/usr/bin/env python3
"""Sign data using GnuPG with hardware token (Nitrokey)."""

from gr_linux_crypto.python.m17_frame import M17SessionKeyExchange

# Ensure Nitrokey is configured in GnuPG
# gpg --card-status
# Should show Nitrokey information

sender_key_id = "0xABCD1234"  # Key ID from Nitrokey

data = b"Important message to sign"

# Sign data
# Will prompt for PIN via pinentry if using hardware token
signed = M17SessionKeyExchange.sign_key_offer(data, sender_key_id)

if signed:
    print("Data signed successfully")
    print(f"Signed data (ASCII-armored): {len(signed)} bytes")
    
    # Verify signature
    is_valid = M17SessionKeyExchange.verify_key_offer_signature(signed)
    print(f"Signature valid: {is_valid}")
else:
    print("Signing failed - check key ID and PIN entry")
```

### Example 3: GNU Radio Block Integration

```python
#!/usr/bin/env python3
"""GNU Radio block using GnuPG for key exchange."""

from gnuradio import gr
import numpy as np
from gr_linux_crypto.python.m17_frame import M17SessionKeyExchange

class GnuPGKeyExchangeBlock(gr.basic_block):
    """Block that performs GnuPG-based key exchange."""
    
    def __init__(self, recipient_key_id):
        gr.basic_block.__init__(
            self,
            name="GnuPG Key Exchange",
            in_sig=None,
            out_sig=[np.uint8]
        )
        self.recipient_key_id = recipient_key_id
        self.session_key = None
    
    def general_work(self, input_items, output_items):
        if self.session_key is None:
            # Generate and encrypt session key
            session_key = M17SessionKeyExchange.generate_session_key()
            encrypted_key = M17SessionKeyExchange.encrypt_key_for_recipient(
                session_key,
                self.recipient_key_id
            )
            
            if encrypted_key:
                self.session_key = session_key
                # Output encrypted key as PDU
                self.consume(0, 0)
                return len(encrypted_key)
            else:
                # Key exchange failed
                return 0
        
        return 0  # Key already exchanged
```

## Custom PIN Input Blocks

When using GnuPG with hardware tokens or protected private keys, PIN entry is required. While GnuPG agent with pinentry works for command-line use, you may want to create custom GNU Radio blocks with integrated PIN input dialogs for better user experience.

### Approach 1: Custom Python Block with GUI Dialog

Create a custom Python block that includes a GUI dialog for entering the GnuPG PIN. This approach provides full control over the PIN entry interface and integrates seamlessly with GNU Radio Companion.

#### Basic PIN Dialog Implementation

```python
#!/usr/bin/env python3
"""Custom GNU Radio block with PIN input dialog."""

from PyQt5 import QtWidgets, QtCore
from PyQt5.QtWidgets import QDialog, QVBoxLayout, QLineEdit, QPushButton, QLabel
from gnuradio import gr
import numpy as np

class PinInputDialog(QtWidgets.QDialog):
    """Dialog for entering GnuPG PIN."""
    
    def __init__(self, parent=None, prompt="Enter GnuPG PIN"):
        super().__init__(parent)
        self.setWindowTitle("GnuPG PIN Entry")
        self.pin = None
        self.cancelled = False
        
        layout = QVBoxLayout()
        
        # Prompt label
        label = QLabel(prompt)
        layout.addWidget(label)
        
        # PIN input field (password mode)
        self.pin_input = QLineEdit(self)
        self.pin_input.setEchoMode(QLineEdit.Password)
        self.pin_input.returnPressed.connect(self.submit_pin)
        layout.addWidget(self.pin_input)
        
        # Submit button
        self.submit_button = QPushButton("Submit")
        self.submit_button.clicked.connect(self.submit_pin)
        layout.addWidget(self.submit_button)
        
        # Cancel button
        cancel_button = QPushButton("Cancel")
        cancel_button.clicked.connect(self.cancel)
        layout.addWidget(cancel_button)
        
        self.setLayout(layout)
        self.pin_input.setFocus()
    
    def submit_pin(self):
        """Submit PIN and close dialog."""
        self.pin = self.pin_input.text()
        self.accept()
    
    def cancel(self):
        """Cancel PIN entry."""
        self.cancelled = True
        self.reject()
    
    def get_pin(self):
        """Get entered PIN."""
        return self.pin if not self.cancelled else None


class GnuPGBlockWithPIN(gr.sync_block):
    """GNU Radio block that requires PIN input for GnuPG operations."""
    
    def __init__(self, key_id, operation='decrypt'):
        gr.sync_block.__init__(
            self,
            name="GnuPG with PIN",
            in_sig=[np.uint8],
            out_sig=[np.uint8]
        )
        self.key_id = key_id
        self.operation = operation
        self.pin = None
    
    def get_pin_from_user(self):
        """Display PIN dialog and get PIN from user."""
        dialog = PinInputDialog(parent=None, prompt=f"Enter PIN for key {self.key_id}")
        
        if dialog.exec_() == QDialog.Accepted:
            return dialog.get_pin()
        return None
    
    def work(self, input_items, output_items):
        """Process data using GnuPG with PIN."""
        if not self.pin:
            self.pin = self.get_pin_from_user()
            if not self.pin:
                # User cancelled, output zeros
                output_items[0][:] = 0
                return len(output_items[0])
        
        # Perform GnuPG operation using subprocess (as per current implementation)
        from gr_linux_crypto.python.m17_frame import M17SessionKeyExchange
        data = bytes(input_items[0])
        
        # Decrypt using session key exchange method
        result = M17SessionKeyExchange.decrypt_key(data)
        
        if result:
            output = np.frombuffer(result, dtype=np.uint8)
            output_items[0][:len(output)] = output[:len(output_items[0])]
        else:
            output_items[0][:] = 0
        
        return len(output_items[0])
```

### Approach 2: Alphanumeric Keypad Input

For systems with physical keypads (embedded systems, industrial panels), you can create a custom keypad interface:

```python
#!/usr/bin/env python3
"""PIN input using alphanumeric keypad interface."""

from PyQt5 import QtWidgets, QtCore
from PyQt5.QtWidgets import (QDialog, QVBoxLayout, QGridLayout, 
                             QPushButton, QLineEdit, QLabel)

class KeypadDialog(QtWidgets.QDialog):
    """Numeric keypad dialog for PIN entry."""
    
    def __init__(self, parent=None, prompt="Enter PIN"):
        super().__init__(parent)
        self.setWindowTitle("Keypad PIN Entry")
        self.pin = ""
        self.cancelled = False
        
        main_layout = QVBoxLayout()
        
        # Prompt label
        label = QLabel(prompt)
        main_layout.addWidget(label)
        
        # PIN display (masked)
        self.pin_display = QLineEdit(self)
        self.pin_display.setReadOnly(True)
        self.pin_display.setEchoMode(QLineEdit.Password)
        self.pin_display.setPlaceholderText("Enter PIN using keypad")
        main_layout.addWidget(self.pin_display)
        
        # Keypad layout
        keypad_layout = QGridLayout()
        
        # Number pad (0-9)
        buttons = [
            ['7', '8', '9'],
            ['4', '5', '6'],
            ['1', '2', '3'],
            ['Clear', '0', 'Enter']
        ]
        
        for i, row in enumerate(buttons):
            for j, text in enumerate(row):
                btn = QPushButton(text)
                if text.isdigit():
                    btn.clicked.connect(lambda checked, digit=text: self.add_digit(digit))
                elif text == 'Clear':
                    btn.clicked.connect(self.clear)
                elif text == 'Enter':
                    btn.clicked.connect(self.submit_pin)
                keypad_layout.addWidget(btn, i, j)
        
        main_layout.addLayout(keypad_layout)
        self.setLayout(main_layout)
    
    def add_digit(self, digit):
        """Add digit to PIN."""
        self.pin += digit
        self.update_display()
    
    def clear(self):
        """Clear PIN."""
        self.pin = ""
        self.update_display()
    
    def update_display(self):
        """Update PIN display."""
        self.pin_display.setText("*" * len(self.pin))
    
    def submit_pin(self):
        """Submit PIN."""
        if self.pin:
            self.accept()
        else:
            QtWidgets.QMessageBox.warning(self, "Error", "PIN cannot be empty")
    
    def get_pin(self):
        """Get entered PIN."""
        return self.pin if not self.cancelled else None


class AlphanumericKeypadDialog(QtWidgets.QDialog):
    """Full alphanumeric keypad (letters and numbers) for PIN/passphrase entry."""
    
    def __init__(self, parent=None, prompt="Enter Passphrase"):
        super().__init__(parent)
        self.setWindowTitle("Alphanumeric Keypad")
        self.input_text = ""
        self.cancelled = False
        
        main_layout = QVBoxLayout()
        
        # Prompt label
        label = QLabel(prompt)
        main_layout.addWidget(label)
        
        # Input display (masked for PINs, visible for passphrases)
        self.display = QLineEdit(self)
        self.display.setReadOnly(True)
        self.display.setEchoMode(QLineEdit.Password)  # Use Password for PINs
        main_layout.addWidget(self.display)
        
        # Create keypad with alphanumeric characters
        keypad_layout = QGridLayout()
        
        # Layout: Numbers first row, then letters in rows
        # Row 1: Numbers
        num_row = ['1', '2', '3', '4', '5', '6', '7', '8', '9', '0']
        for i, char in enumerate(num_row):
            btn = QPushButton(char)
            btn.clicked.connect(lambda checked, c=char: self.add_char(c))
            keypad_layout.addWidget(btn, 0, i)
        
        # Row 2-4: Letters (Q-Z, A-P split across rows)
        letter_rows = [
            ['Q', 'W', 'E', 'R', 'T', 'Y', 'U', 'I', 'O', 'P'],
            ['A', 'S', 'D', 'F', 'G', 'H', 'J', 'K', 'L'],
            ['Z', 'X', 'C', 'V', 'B', 'N', 'M']
        ]
        
        for row_idx, row in enumerate(letter_rows, start=1):
            for col_idx, char in enumerate(row):
                btn = QPushButton(char)
                btn.clicked.connect(lambda checked, c=char: self.add_char(c))
                keypad_layout.addWidget(btn, row_idx, col_idx)
        
        # Bottom row: Control buttons
        clear_btn = QPushButton("Clear")
        clear_btn.clicked.connect(self.clear)
        keypad_layout.addWidget(clear_btn, 5, 0, 1, 3)
        
        space_btn = QPushButton("Space")
        space_btn.clicked.connect(lambda: self.add_char(' '))
        keypad_layout.addWidget(space_btn, 5, 3, 1, 4)
        
        enter_btn = QPushButton("Enter")
        enter_btn.clicked.connect(self.submit)
        keypad_layout.addWidget(enter_btn, 5, 7, 1, 3)
        
        main_layout.addLayout(keypad_layout)
        self.setLayout(main_layout)
    
    def add_char(self, char):
        """Add character to input."""
        self.input_text += char
        self.update_display()
    
    def clear(self):
        """Clear input."""
        self.input_text = ""
        self.update_display()
    
    def update_display(self):
        """Update display."""
        # Show masked characters for security
        self.display.setText("*" * len(self.input_text))
    
    def submit(self):
        """Submit input."""
        if self.input_text:
            self.accept()
        else:
            QtWidgets.QMessageBox.warning(self, "Error", "Input cannot be empty")
    
    def get_input(self):
        """Get entered text."""
        return self.input_text if not self.cancelled else None
```

### Approach 3: Touch Screen Interface

For touch screen devices, you can create a larger, touch-friendly interface:

```python
#!/usr/bin/env python3
"""Touch screen optimized PIN input interface."""

from PyQt5 import QtWidgets, QtCore, QtGui
from PyQt5.QtWidgets import (QDialog, QVBoxLayout, QGridLayout,
                             QPushButton, QLineEdit, QLabel)
from PyQt5.QtCore import Qt

class TouchScreenPinDialog(QtWidgets.QDialog):
    """Touch-optimized PIN entry dialog with large buttons."""
    
    def __init__(self, parent=None, prompt="Enter PIN"):
        super().__init__(parent)
        self.setWindowTitle("Touch Screen PIN Entry")
        self.pin = ""
        self.cancelled = False
        
        # Make dialog fullscreen or large for touch
        if parent:
            self.setWindowFlags(Qt.FramelessWindowHint | Qt.WindowStaysOnTopHint)
        
        main_layout = QVBoxLayout()
        
        # Prompt label (large font for visibility)
        label = QLabel(prompt)
        label.setAlignment(Qt.AlignCenter)
        font = label.font()
        font.setPointSize(18)
        label.setFont(font)
        main_layout.addWidget(label)
        
        # PIN display (large)
        self.pin_display = QLineEdit(self)
        self.pin_display.setReadOnly(True)
        self.pin_display.setEchoMode(QLineEdit.Password)
        font = self.pin_display.font()
        font.setPointSize(24)
        self.pin_display.setFont(font)
        self.pin_display.setMinimumHeight(60)
        main_layout.addWidget(self.pin_display)
        
        # Touch-optimized keypad with large buttons
        keypad_layout = QGridLayout()
        keypad_layout.setSpacing(10)
        
        # Number pad configuration
        buttons = [
            ['7', '8', '9'],
            ['4', '5', '6'],
            ['1', '2', '3'],
            ['Clear', '0', 'Enter']
        ]
        
        # Create large buttons suitable for touch
        for i, row in enumerate(buttons):
            for j, text in enumerate(row):
                btn = QPushButton(text)
                
                # Large font for touch screens
                font = btn.font()
                font.setPointSize(20)
                font.setBold(True)
                btn.setFont(font)
                
                # Large button size (minimum 80x80 pixels for touch)
                btn.setMinimumSize(80, 80)
                
                # Style for better touch feedback
                btn.setStyleSheet("""
                    QPushButton {
                        background-color: #f0f0f0;
                        border: 2px solid #ccc;
                        border-radius: 10px;
                    }
                    QPushButton:pressed {
                        background-color: #d0d0d0;
                        border: 3px solid #888;
                    }
                """)
                
                if text.isdigit():
                    btn.clicked.connect(lambda checked, digit=text: self.add_digit(digit))
                elif text == 'Clear':
                    btn.clicked.connect(self.clear)
                elif text == 'Enter':
                    btn.clicked.connect(self.submit_pin)
                
                keypad_layout.addWidget(btn, i, j)
        
        main_layout.addLayout(keypad_layout)
        self.setLayout(main_layout)
    
    def add_digit(self, digit):
        """Add digit to PIN."""
        self.pin += digit
        self.update_display()
        # Haptic feedback on touch devices (if supported)
        QtWidgets.QApplication.beep()
    
    def clear(self):
        """Clear PIN."""
        self.pin = ""
        self.update_display()
    
    def update_display(self):
        """Update PIN display."""
        self.pin_display.setText("*" * len(self.pin))
    
    def submit_pin(self):
        """Submit PIN."""
        if self.pin:
            self.accept()
        else:
            msg = QtWidgets.QMessageBox(self)
            msg.setIcon(QtWidgets.QMessageBox.Warning)
            msg.setText("PIN cannot be empty")
            msg.setWindowTitle("Error")
            msg.exec_()
    
    def get_pin(self):
        """Get entered PIN."""
        return self.pin if not self.cancelled else None


class TouchScreenAlphanumericDialog(QtWidgets.QDialog):
    """Touch-optimized alphanumeric keyboard."""
    
    def __init__(self, parent=None, prompt="Enter Passphrase"):
        super().__init__(parent)
        self.setWindowTitle("Touch Keyboard")
        self.input_text = ""
        
        # Fullscreen for touch devices
        if parent:
            self.setWindowFlags(Qt.FramelessWindowHint | Qt.WindowStaysOnTopHint)
        
        main_layout = QVBoxLayout()
        
        # Prompt
        label = QLabel(prompt)
        label.setAlignment(Qt.AlignCenter)
        font = label.font()
        font.setPointSize(16)
        label.setFont(font)
        main_layout.addWidget(label)
        
        # Input display
        self.display = QLineEdit(self)
        self.display.setReadOnly(True)
        self.display.setEchoMode(QLineEdit.Password)
        font = self.display.font()
        font.setPointSize(20)
        self.display.setFont(font)
        self.display.setMinimumHeight(50)
        main_layout.addWidget(self.display)
        
        # Touch-optimized keyboard
        keyboard_layout = QVBoxLayout()
        
        # Numbers row
        num_layout = QGridLayout()
        numbers = ['1', '2', '3', '4', '5', '6', '7', '8', '9', '0']
        for i, num in enumerate(numbers):
            btn = self.create_touch_button(num)
            btn.clicked.connect(lambda checked, c=num: self.add_char(c))
            num_layout.addWidget(btn, 0, i)
        keyboard_layout.addLayout(num_layout)
        
        # Letters in rows (QWERTY layout)
        letter_rows = [
            ['Q', 'W', 'E', 'R', 'T', 'Y', 'U', 'I', 'O', 'P'],
            ['A', 'S', 'D', 'F', 'G', 'H', 'J', 'K', 'L'],
            ['Z', 'X', 'C', 'V', 'B', 'N', 'M']
        ]
        
        for row in letter_rows:
            row_layout = QGridLayout()
            for i, char in enumerate(row):
                btn = self.create_touch_button(char)
                btn.clicked.connect(lambda checked, c=char: self.add_char(c))
                row_layout.addWidget(btn, 0, i)
            keyboard_layout.addLayout(row_layout)
        
        # Control buttons row
        control_layout = QGridLayout()
        
        clear_btn = self.create_touch_button("Clear", width_factor=2)
        clear_btn.clicked.connect(self.clear)
        control_layout.addWidget(clear_btn, 0, 0)
        
        space_btn = self.create_touch_button("Space", width_factor=3)
        space_btn.clicked.connect(lambda: self.add_char(' '))
        control_layout.addWidget(space_btn, 0, 2)
        
        enter_btn = self.create_touch_button("Enter", width_factor=2)
        enter_btn.clicked.connect(self.submit)
        control_layout.addWidget(enter_btn, 0, 5)
        
        keyboard_layout.addLayout(control_layout)
        main_layout.addLayout(keyboard_layout)
        self.setLayout(main_layout)
    
    def create_touch_button(self, text, width_factor=1):
        """Create a touch-optimized button."""
        btn = QPushButton(text)
        font = btn.font()
        font.setPointSize(18)
        btn.setFont(font)
        btn.setMinimumSize(60 * width_factor, 60)
        btn.setStyleSheet("""
            QPushButton {
                background-color: #f0f0f0;
                border: 2px solid #ccc;
                border-radius: 8px;
                padding: 10px;
            }
            QPushButton:pressed {
                background-color: #d0d0d0;
                border: 3px solid #888;
            }
        """)
        return btn
    
    def add_char(self, char):
        """Add character to input."""
        self.input_text += char
        self.update_display()
    
    def clear(self):
        """Clear input."""
        self.input_text = ""
        self.update_display()
    
    def update_display(self):
        """Update display."""
        self.display.setText("*" * len(self.input_text))
    
    def submit(self):
        """Submit input."""
        if self.input_text:
            self.accept()
    
    def get_input(self):
        """Get entered text."""
        return self.input_text
```

### Integration Example

Here's how to use these dialogs in a GNU Radio block:

```python
#!/usr/bin/env python3
"""Example: Using custom PIN dialogs in GNU Radio block."""

from gnuradio import gr
import numpy as np
from gr_linux_crypto.python.m17_frame import M17SessionKeyExchange
from PyQt5.QtWidgets import QDialog

class GnuPGBlockWithCustomPIN(gr.sync_block):
    """GNU Radio block with custom PIN input."""
    
    def __init__(self, key_id, dialog_type='standard'):
        """
        Args:
            key_id: GnuPG key ID
            dialog_type: 'standard', 'keypad', 'touch', or 'alphanumeric'
        """
        gr.sync_block.__init__(
            self,
            name="GnuPG Custom PIN",
            in_sig=[np.uint8],
            out_sig=[np.uint8]
        )
        self.key_id = key_id
        self.dialog_type = dialog_type
        self.pin = None
    
    def get_pin(self):
        """Get PIN using appropriate dialog."""
        from PyQt5 import QtWidgets
        
        if self.dialog_type == 'keypad':
            dialog = KeypadDialog(prompt=f"Enter PIN for {self.key_id}")
        elif self.dialog_type == 'touch':
            dialog = TouchScreenPinDialog(prompt=f"Enter PIN for {self.key_id}")
        elif self.dialog_type == 'alphanumeric':
            dialog = AlphanumericKeypadDialog(prompt=f"Enter passphrase for {self.key_id}")
        else:  # standard
            dialog = PinInputDialog(prompt=f"Enter PIN for {self.key_id}")
        
        if dialog.exec_() == QDialog.Accepted:
            return dialog.get_pin()
        return None
    
    def work(self, input_items, output_items):
        """Process with GnuPG using custom PIN entry."""
        if not self.pin:
            self.pin = self.get_pin()
            if not self.pin:
                output_items[0][:] = 0
                return len(output_items[0])
        
        # Perform GnuPG operation
        data = bytes(input_items[0])
        
        # Note: PIN handling with subprocess-based GnuPG requires
        # integration with gpg-agent or environment variables
        result = M17SessionKeyExchange.decrypt_key(data)
        
        if result:
            output = np.frombuffer(result, dtype=np.uint8)
            output_items[0][:len(output)] = output[:len(output_items[0])]
        else:
            output_items[0][:] = 0
        
        return len(output_items[0])
```

### Using the Custom Block

1. **In GNU Radio Companion:**
   - Save the custom block code as a Python file
   - Import it in your flowgraph
   - Add the block to your flowgraph
   - The PIN dialog will appear automatically when needed

2. **For Embedded/Headless Systems:**
   - Use the alphanumeric keypad version for physical keypads
   - Use the touch screen version for touch-enabled devices
   - Ensure PyQt5 is available in your environment

3. **Security Considerations:**
   - PIN is stored in memory only during operation
   - Clear PIN from memory after use
   - Use masked display (password mode) for PIN entry
   - Consider implementing PIN attempt limits

## Troubleshooting

### Common Issues

**1. "GnuPG not available" error**
```bash
# Check if gpg is installed
which gpg

# Check GnuPG version
gpg --version

# Test basic operation
echo "test" | gpg --encrypt --recipient your@email.com
```

**2. PIN entry not working**
```bash
# Check if gpg-agent is running
gpg-connect-agent --version

# Check pinentry configuration
cat ~/.gnupg/gpg-agent.conf

# Test PIN entry
gpg --card-status  # For smart cards
# OR
gpg --list-secret-keys  # For protected private keys

# Restart agent if needed
gpg-connect-agent reloadagent /bye
```

**3. "No secret key" error**
```bash
# List secret keys
gpg --list-secret-keys

# Import missing key
gpg --import private_key.asc

# Check key trust
gpg --list-keys
```

**4. Smart card not detected**
```bash
# Check if pcscd is running
sudo systemctl status pcscd

# Start pcscd if needed
sudo systemctl start pcscd

# Check card status
gpg --card-status

# Enable reader in scdaemon.conf
echo "reader-port Yubico" >> ~/.gnupg/scdaemon.conf
```

**5. Timeout errors in subprocess calls**
```python
# Increase timeout in M17SessionKeyExchange methods
# Default is 5 seconds, may need more for hardware tokens
result = subprocess.run(
    ['gpg', '--decrypt'],
    input=encrypted_key,
    capture_output=True,
    timeout=30  # Increase timeout
)
```

### Debug Mode

Enable verbose GnuPG output:
```bash
# Set debug level
export GPG_AGENT_INFO=""
gpg --debug-level expert --decrypt file.gpg

# Or in Python
import os
os.environ['GPG_AGENT_INFO'] = ''
```

## Contributing

If you would like to contribute improvements to GnuPG integration:

1. Check existing issues and pull requests
2. Propose changes via GitHub issues
3. Submit pull requests with tests
4. Follow the module's coding standards

## Legal and Appropriate Uses for Amateur Radio

### GnuPG/OpenPGP Operations in Amateur Radio

**Important Legal Considerations:**

1. **Digital Signatures (Primary Use Case)**

   - Cryptographically sign transmissions to verify sender identity
   - Prevent callsign spoofing
   - Replace error-prone DTMF authentication
   - **Legal**: Digital signatures do not obscure content and are generally permitted

2. **Message Integrity**

   - Detect transmission errors
   - Verify message authenticity
   - Non-obscuring authentication tags
   - **Legal**: Integrity verification does not hide message content

3. **Key Management Infrastructure**

   - Secure key storage (Nitrokey, kernel keyring)
   - Off-air key exchange (ECDH)
   - Authentication key distribution
   - **Legal**: Key management does not encrypt on-air content

### Experimental and Research Uses

For experiments or research on frequencies where encryption is legally permitted:

- Encryption may be used in accordance with local regulations
- Users must verify applicable frequency bands and regulations
- This module provides the technical capability; users are responsible for legal compliance

### User Responsibility

**Critical:** Users must check local regulations before using cryptographic features.

- Encryption regulations vary by country and jurisdiction
- Frequency bands have different rules (amateur, ISM, experimental allocations)
- **The responsibility for legal compliance is 100% the user's**
- This module and its developers assume no liability for improper use
- Consult with local regulatory authorities (FCC, OFCOM, etc.) for specific requirements

### Resources for Regulatory Information

- **United States:** [FCC Part 97 Rules](https://www.fcc.gov/wireless/bureau-divisions/mobility-division/amateur-radio-service/part-97-amateur-radio)
- **United Kingdom:** [OFCOM Amateur Radio Licensing](https://www.ofcom.org.uk/manage-your-licence/radiocommunication-licences/amateur-radio)
- **International:** Check with your national telecommunications authority

**Disclaimer:** The information provided here is for general guidance only. Always consult current regulations for your specific jurisdiction and use case.

## References

- [GnuPG Documentation](https://www.gnupg.org/documentation/)
- [GnuPG Agent Manual](https://www.gnupg.org/documentation/manuals/gnupg/GPG-Agent.html)
- [Pinentry Programs](https://www.gnupg.org/documentation/manuals/gnupg/Pinentry.html)
- [Smart Card Setup](https://wiki.gnupg.org/SmartCard)

## See Also

- [Usage Flowchart](USAGE_FLOWCHART.md) - General module usage
- [Architecture Documentation](architecture.md) - Module architecture
- [Examples](examples.md) - Code examples

