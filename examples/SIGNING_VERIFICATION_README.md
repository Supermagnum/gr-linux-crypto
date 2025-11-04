# Signing and Verification Examples

This document explains the signing and verification examples in the `signing_verification/` folder and how to use them for TX/RX operations.

## Contents of `signing_verification/` Folder

The `signing_verification/` folder contains GNU Radio Companion (GRC) flowgraphs that demonstrate digital signing and verification using Ed25519 signatures with Nitrokey or Linux kernel keyring.

### Available Examples

#### APRS (Automatic Packet Reporting System)
- **`aprs_nitrokey_signing.grc`**: Signs APRS messages using Ed25519 private key from Nitrokey slot
- **`aprs_nitrokey_verification.grc`**: Verifies APRS message signatures using Ed25519 public key from Nitrokey slot
- **`aprs_kernel_keyring_signing.grc`**: Signs APRS messages using Ed25519 private key from Linux kernel keyring
- **`aprs_kernel_keyring_verification.grc`**: Verifies APRS message signatures using Ed25519 public key from Linux kernel keyring

#### MFSK (Multi-Frequency Shift Keying)
- **`MFSK_nitrokey_nacl_signing.grc`**: Signs MFSK messages using Ed25519 private key from Nitrokey slot
- **`mfsk_nitrokey_verification.grc`**: Verifies MFSK message signatures using Ed25519 public key from Nitrokey slot
- **`mfsk_kernel_keyring_verification.grc`**: Verifies MFSK message signatures using Ed25519 public key from Linux kernel keyring

#### FreeDV (Digital Voice)
- **`freedv_nitrokey_signing.grc`**: Signs FreeDV voice data using Ed25519 private key from Nitrokey slot
- **`freedv_nitrokey_verification.grc`**: Verifies FreeDV voice data signatures using Ed25519 public key from Nitrokey slot

## How Digital Signing Works

### Signing Process (TX)
1. Message/data is prepared (text message or voice codec output)
2. Ed25519 private key is loaded from Nitrokey slot or kernel keyring
3. Message is signed using gr-nacl Ed25519 signing function
4. 64-byte Ed25519 signature is appended to the message
5. Signed message (original + signature) is modulated and transmitted

### Verification Process (RX)
1. Signed message is received and demodulated
2. Message and signature are separated (last 64 bytes = signature)
3. Ed25519 public key is loaded from Nitrokey slot or kernel keyring
4. Signature is verified using gr-nacl Ed25519 verification function
5. Verification result is printed to console
6. Original message (without signature) is output if verification succeeds

## Creating TX/RX Flowgraphs

### Basic TX Flowgraph (Signing)

1. **Message Source**: Use `blocks_vector_source_x` with text message or `audio_source` for voice
2. **Key Source**: Use `linux_crypto_nitrokey_interface` (Nitrokey) or `linux_crypto_kernel_keyring_source` (kernel keyring)
3. **Signing Block**: Use embedded Python block (`epy_block`) that:
   - Takes message and private key as inputs
   - Signs message using gr-nacl `sign_ed25519()`
   - Outputs message + 64-byte signature
4. **Modulation**: Add appropriate modulator (MFSK, AFSK, FreeDV)
5. **Radio Output**: Replace file sink with radio hardware (USRP, SDR, audio sink)

### Basic RX Flowgraph (Verification)

1. **Radio Input**: Replace file source with radio hardware (USRP, SDR, audio source)
2. **Demodulation**: Add appropriate demodulator matching the modulation used
3. **Key Source**: Use `linux_crypto_nitrokey_interface` (Nitrokey) or `linux_crypto_kernel_keyring_source` (kernel keyring)
4. **Verification Block**: Use embedded Python block (`epy_block`) that:
   - Takes signed message and public key as inputs
   - Extracts message (all but last 64 bytes) and signature (last 64 bytes)
   - Verifies signature using gr-nacl `verify_ed25519()`
   - Prints verification result to console
   - Outputs original message if verification succeeds

### Example TX Flowgraph Structure

```
Message Text Entry
    ↓
Vector Source (converts text to bytes)
    ↓
[Nitrokey Interface] → [Signing Block] ← Message bytes
    ↓
Signed Message (message + 64-byte signature)
    ↓
Modulator (MFSK/AFSK/FreeDV)
    ↓
Radio Hardware (USRP/SDR/Audio Sink)
```

### Example RX Flowgraph Structure

```
Radio Hardware (USRP/SDR/Audio Source)
    ↓
Demodulator (MFSK/AFSK/FreeDV)
    ↓
[Nitrokey Interface] → [Verification Block] ← Signed message bytes
    ↓
Verified Message (original message without signature)
    ↓
Output (display/text/audio)
```

## Key Configuration

### Nitrokey Setup
1. Generate Ed25519 key pair or import existing key
2. Store private key in Nitrokey slot (0-15)
3. Export public key and store in Nitrokey slot or file
4. Configure slot number in GRC flowgraph

### Kernel Keyring Setup
1. Store Ed25519 private key in kernel keyring:
   ```bash
   keyctl add user ed25519_privkey <key_data> @u
   ```
2. Get key ID:
   ```bash
   keyctl show @u
   ```
3. Store public key similarly
4. Configure key ID in GRC flowgraph

## Button-Based Signing

To sign only when a button is pressed, you can use one of these approaches:

### Method 1: QT GUI Push Button with Message Source

1. **Add QT GUI Push Button Block** (`qtgui_push_button`):
   - Configure button label (e.g., "Sign and Transmit")
   - Connect button output to message source trigger

2. **Use Message Source Instead of Vector Source**:
   - Replace `blocks_vector_source_x` with `blocks_message_source`
   - Configure message source to emit message bytes when triggered
   - Connect button output to message source trigger input

3. **Flow Structure**:
   ```
   QT GUI Push Button
       ↓ (triggers on press)
   Message Source (emits message bytes)
       ↓
   [Signing Block]
       ↓
   Modulator → Radio
   ```

### Method 2: Embedded Python Block with State Control

1. **Add QT GUI Push Button** (`qtgui_push_button`)
2. **Create Python Block** that:
   - Receives button press messages via message port
   - Maintains internal state (message buffer)
   - Only signs and outputs when button is pressed
   - Clears buffer after transmission

3. **Python Block Structure**:
   ```python
   class blk(gr.sync_block):
       def __init__(self):
           gr.sync_block.__init__(
               self,
               name='Button-Controlled Signer',
               in_sig=[np.uint8, np.uint8],  # message, key
               out_sig=[np.uint8]
           )
           self.message_port_register_in(pmt.intern("button"))
           self.set_msg_handler(pmt.intern("button"), self.handle_button)
           self._message_buffer = bytearray()
           self._key_buffer = bytearray()
           self._transmit = False
       
       def handle_button(self, msg):
           # Called when button is pressed
           self._transmit = True
       
       def work(self, input_items, output_items):
           # Collect message and key
           # When _transmit is True, sign and output
           # Set _transmit = False after transmission
   ```

### Method 3: QT GUI Range Slider as Trigger

1. **Use QT GUI Range Slider** (`variable_qtgui_range`)
2. **Set range**: 0 (idle) to 1 (transmit)
3. **Connect slider value to message source** or use as trigger in Python block
4. **User slides to 1 to trigger signing and transmission**

## TX/RX Toggle with Push Button

To toggle between transmission (TX) and reception (RX) modes using a push button, you can use one of these approaches:

### Method 1: QT GUI Toggle Button with Selector Block

1. **Add QT GUI Toggle Button** (`variable_qtgui_toggle_button`):
   - Configure button label (e.g., "TX/RX Toggle")
   - Set initial state: `False` (RX) or `True` (TX)
   - The button value will be `True` when pressed (TX mode) and `False` when released (RX mode)

2. **Add Selector Block** (`blocks_selector`) or **Throttle Block**:
   - Use selector to route data between TX and RX paths
   - Or use throttle blocks to enable/disable TX and RX paths based on button state

3. **Flow Structure**:
   ```
   QT GUI Toggle Button (TX/RX state)
       ↓
   [Selector Block] → Routes to TX or RX path
       ↓
   TX Path: Audio Source → Signing → Modulator → Radio Sink
   RX Path: Radio Source → Demodulator → Verification → Audio Sink
   ```

### Method 2: Message-Based Toggle with Embedded Python Block

1. **Add QT GUI Push Button** (`qtgui_push_button`) or **Toggle Button** (`variable_qtgui_toggle_button`)

2. **Create Python Block** that:
   - Receives button state via message port
   - Maintains internal TX/RX state
   - Routes data to appropriate output port based on state
   - Can enable/disable TX or RX processing

3. **Python Block Structure**:
   ```python
   import numpy as np
   from gnuradio import gr
   import pmt
   
   class blk(gr.sync_block):
       def __init__(self):
           gr.sync_block.__init__(
               self,
               name='TX/RX Toggle',
               in_sig=[np.uint8],  # Input from radio or audio
               out_sig=[np.uint8, np.uint8]  # TX output, RX output
           )
           self.message_port_register_in(pmt.intern("toggle"))
           self.set_msg_handler(pmt.intern("toggle"), self.handle_toggle)
           self._tx_mode = False  # False = RX, True = TX
       
       def handle_toggle(self, msg):
           # Toggle between TX and RX
           self._tx_mode = not self._tx_mode
           print(f"Mode: {'TX' if self._tx_mode else 'RX'}")
       
       def work(self, input_items, output_items):
           n = len(input_items[0])
           
           if self._tx_mode:
               # TX mode: output to TX path, zero RX
               output_items[0][:n] = input_items[0]
               output_items[1][:n] = 0
           else:
               # RX mode: output to RX path, zero TX
               output_items[0][:n] = 0
               output_items[1][:n] = input_items[0]
           
           return n
   ```

### Method 3: Separate TX and RX Flowgraphs with Button Control

1. **Create Two Separate Flowgraphs**:
   - `tx_flowgraph.grc`: Signing and transmission path
   - `rx_flowgraph.grc`: Reception and verification path

2. **Add QT GUI Push Button** to each:
   - TX flowgraph: Button enables/disables transmission
   - RX flowgraph: Button enables/disables reception

3. **Use Throttle Blocks** or **Message Strobe**:
   - Connect button to throttle block to enable/disable data flow
   - When button is pressed (TX mode), enable TX throttle, disable RX throttle
   - When button is released (RX mode), disable TX throttle, enable RX throttle

### Method 4: PTT (Push-To-Talk) Style Button

For a traditional PTT button that only transmits when held:

1. **Add QT GUI Push Button** (`qtgui_push_button`):
   - Button emits message when pressed and released
   - Use `variable_qtgui_push_button` with message output

2. **Message Handler**:
   - On button press: Enable TX path, disable RX path
   - On button release: Disable TX path, enable RX path

3. **Flow Structure**:
   ```
   Push Button (PTT)
       ↓ (message on press/release)
   [Message Handler Block]
       ↓
   Controls TX/RX selector or throttle blocks
   ```

### Example: Complete TX/RX Toggle Flowgraph Structure

```
Audio Source (microphone)
    ↓
[Signing Block] ← Nitrokey (private key)
    ↓
[TX/RX Toggle Block] ← Button input
    ↓
TX Path → Modulator → Radio Sink
RX Path ← Demodulator ← Radio Source
    ↓
[Verification Block] ← Nitrokey (public key)
    ↓
Audio Sink (speaker)
```

### Implementation Notes

1. **Radio Hardware**: Ensure your radio hardware supports full-duplex operation if you want simultaneous TX/RX capability, or use half-duplex (PTT) mode where TX and RX are mutually exclusive.

2. **State Management**: When toggling modes, consider:
   - Buffering any data in transit
   - Clearing buffers when switching modes
   - Handling partial frames/signatures

3. **Button Debouncing**: In software, you may want to add debouncing logic to prevent rapid toggling if the button is pressed multiple times quickly.

4. **Visual Feedback**: Use QT GUI labels or indicators to show current mode (TX/RX) to the user.

## FreeDV Signing Examples

FreeDV signing and verification flowgraphs can be created following the same pattern as the APRS and MFSK examples. The structure is:

### FreeDV Signing Flow

1. **Audio Input** → Resample to 8 kHz → Codec2 Encoder
2. **Codec2 frames** → Signing Block (with Nitrokey private key)
3. **Signed frames** → FreeDV Modulator → Radio Output

### FreeDV Verification Flow

1. **Radio Input** → FreeDV Demodulator
2. **Demodulated data** → Verification Block (with Nitrokey public key)
3. **Verified Codec2 frames** → Codec2 Decoder → Audio Output

Note: FreeDV signing signs individual Codec2 frames (8 bytes each for 3200 bps mode), so each frame has its own signature appended.

## Testing Workflow

### Step 1: Prepare Keys
```bash
# For Nitrokey: Store Ed25519 keys in Nitrokey slots
# For kernel keyring: Store keys using keyctl
keyctl add user ed25519_privkey <private_key_data> @u
keyctl add user ed25519_pubkey <public_key_data> @u
```

### Step 2: Test Signing (TX)
1. Open signing flowgraph in GRC
2. Configure Nitrokey slot or kernel keyring key ID
3. Enter message text (or use audio input for voice)
4. Run flowgraph
5. Check output file or radio transmission
6. Verify console output shows "Message signed: X bytes + 64 byte signature"

### Step 3: Test Verification (RX)
1. Open verification flowgraph in GRC
2. Configure Nitrokey slot or kernel keyring key ID (must match TX side)
3. Set signed message file path (or use radio input)
4. Run flowgraph
5. Check console for verification result:
   - "VERIFIED: message signature is VALID"
   - "FAILED: message signature is INVALID"

## Integration with Radio Hardware

### Replacing File Sinks/Sources

**For TX (Signing Flowgraphs):**
- Remove `blocks_file_sink` block
- Add radio sink block:
  - `UHD USRP Sink` (for Ettus USRP radios)
  - `Soapy SDR Sink` (for SoapySDR-compatible radios)
  - `audio_sink` (for sound card transmission)
- Connect modulated signal output to radio sink
- Configure frequency, sample rate, and gain

**For RX (Verification Flowgraphs):**
- Remove `blocks_file_source` block
- Add radio source block:
  - `UHD USRP Source` (for Ettus USRP radios)
  - `Soapy SDR Source` (for SoapySDR-compatible radios)
  - `audio_source` (for sound card reception)
- Add demodulator block matching the modulation used
- Connect radio source → demodulator → verification block

### Adding Demodulators

**For MFSK:**
- Add MFSK demodulator block (from `gr-digital` or appropriate module)
- Configure symbol rate and bits per symbol to match TX side

**For APRS:**
- Add AFSK (Bell 202) demodulator
- Configure baud rate (typically 1200 baud)
- Add AX.25 frame parser if needed

**For FreeDV:**
- FreeDV demodulator is already included in verification flowgraphs
- Ensure FreeDV mode matches TX side (e.g., MODE_1600, MODE_700)

## Troubleshooting

### Common Issues

1. **"Signature verification failed"**
   - Check that public key matches private key used for signing
   - Verify Nitrokey slot numbers match on TX and RX
   - Ensure kernel keyring key IDs match
   - Check that message wasn't modified during transmission

2. **"gr-nacl not available"**
   - Install gr-nacl module: `sudo apt install gnuradio-dev gr-nacl` or build from source
   - Verify gr-nacl is in Python path: `python3 -c "from gnuradio import nacl"`

3. **"Nitrokey not found"**
   - Ensure Nitrokey is connected and recognized: `lsusb | grep Nitrokey`
   - Check libnitrokey is installed: `ldconfig -p | grep nitrokey`
   - Verify slot number contains valid Ed25519 key

4. **"Key not found in kernel keyring"**
   - List keys: `keyctl list @u`
   - Verify key ID is correct
   - Ensure key wasn't expired or revoked

## Security Considerations

1. **Private Key Protection**: Never transmit private keys over the air. Only public keys should be shared.

2. **Key Distribution**: Use secure methods to exchange public keys:
   - In-person key exchange
   - Secure digital channels (encrypted email, secure messaging)
   - Key signing parties
   - PGP keyservers (with proper verification)

3. **Signature Verification**: Always verify signatures before trusting received messages. Failed verification indicates:
   - Message was tampered with
   - Wrong key was used
   - Message was signed by different entity

4. **Nonce Management**: For encryption/decryption examples, ensure nonce counters are synchronized between TX and RX.

## References

- Ed25519: High-speed high-security signatures (RFC 8032)
- gr-nacl: GNU Radio module for modern cryptography
- FreeDV: Open source digital voice mode
- APRS: Automatic Packet Reporting System protocol
- MFSK: Multi-Frequency Shift Keying modulation

