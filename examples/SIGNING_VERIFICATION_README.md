# Signing and Verification Examples

This document explains the signing and verification examples in the `signing_verification/` folder and how to use them for TX/RX operations.

## Table of Contents

- [Contents of `signing_verification/` Folder](#contents-of-signing_verification-folder)
  - [Available Examples](#available-examples)
- [How Digital Signing Works](#how-digital-signing-works)
  - [Signing Process (TX)](#signing-process-tx)
  - [Verification Process (RX)](#verification-process-rx)
- [Creating TX/RX Flowgraphs](#creating-txrx-flowgraphs)
  - [Basic TX Flowgraph (Signing)](#basic-tx-flowgraph-signing)
  - [Basic RX Flowgraph (Verification)](#basic-rx-flowgraph-verification)
  - [Example TX Flowgraph Structure](#example-tx-flowgraph-structure)
  - [Example RX Flowgraph Structure](#example-rx-flowgraph-structure)
- [Key Configuration](#key-configuration)
  - [Nitrokey Setup](#nitrokey-setup)
  - [Kernel Keyring Setup](#kernel-keyring-setup)
- [Button-Based Signing](#button-based-signing)
  - [Method 1: QT GUI Push Button with Message Source](#method-1-qt-gui-push-button-with-message-source)
  - [Method 2: Embedded Python Block with State Control](#method-2-embedded-python-block-with-state-control)
  - [Method 3: QT GUI Range Slider as Trigger](#method-3-qt-gui-range-slider-as-trigger)
- [TX/RX Toggle with Push Button](#txrx-toggle-with-push-button)
  - [Method 1: QT GUI Toggle Button with Selector Block](#method-1-qt-gui-toggle-button-with-selector-block)
  - [Method 2: Message-Based Toggle with Embedded Python Block](#method-2-message-based-toggle-with-embedded-python-block)
  - [Method 3: Separate TX and RX Flowgraphs with Button Control](#method-3-separate-tx-and-rx-flowgraphs-with-button-control)
  - [Method 4: PTT (Push-To-Talk) Style Button](#method-4-ptt-push-to-talk-style-button)
  - [Example: Complete TX/RX Toggle Flowgraph Structure](#example-complete-txrx-toggle-flowgraph-structure)
  - [Implementation Notes](#implementation-notes)
- [FreeDV Signing Examples](#freedv-signing-examples)
  - [FreeDV Signing Flow](#freedv-signing-flow)
  - [FreeDV Verification Flow](#freedv-verification-flow)
- [M17 Signing Examples](#m17-signing-examples)
  - [M17 Signing Flow](#m17-signing-flow)
  - [M17 Verification Flow](#m17-verification-flow)
- [Adding a signature frame to the end of a transmission](#adding-a-signature-frame-to-the-end-of-a-transmission)
  - [How Burst Tagging Works](#how-burst-tagging-works)
  - [Burst Tagger Python Block](#burst-tagger-python-block)
  - [GRC Integration with Mode Selection](#grc-integration-with-mode-selection)
  - [Complete Flow Graph Structure](#complete-flow-graph-structure)
  - [Signature Frame at End of Transmission](#signature-frame-at-end-of-transmission)
    - [Why Place the Signature Frame at the End?](#why-place-the-signature-frame-at-the-end)
  - [Optional GPIO PTT Source Block](#optional-gpio-ptt-source-block)
  - [Usage Examples](#usage-examples)
    - [Voice Mode with PTT](#voice-mode-with-ptt)
    - [Data Mode (no PTT)](#data-mode-no-ptt)
    - [Hybrid Mode (PTT + VOX)](#hybrid-mode-ptt--vox)
  - [Testing Configuration](#testing-configuration)
  - [Parameters for Different Use Cases](#parameters-for-different-use-cases)
    - [Voice (PTT)](#voice-ptt)
    - [Voice (VOX)](#voice-vox)
    - [Data Packets](#data-packets)
    - [Repeater Commands](#repeater-commands)
  - [Modifying Signing Blocks for Burst Tagging](#modifying-signing-blocks-for-burst-tagging)
- [Testing Workflow](#testing-workflow)
  - [Step 1: Prepare Keys](#step-1-prepare-keys)
  - [Step 2: Test Signing (TX)](#step-2-test-signing-tx)
  - [Step 3: Test Verification (RX)](#step-3-test-verification-rx)
- [Integration with Radio Hardware](#integration-with-radio-hardware)
  - [Replacing File Sinks/Sources](#replacing-file-sinkssources)
  - [Adding Demodulators](#adding-demodulators)
- [Troubleshooting](#troubleshooting)
  - [Common Issues](#common-issues)
- [Security Considerations](#security-considerations)
- [Encryption/Decryption Examples](#encryptiondecryption-examples)
  - [Available Examples](#available-examples-1)
  - [How Encryption/Decryption Works](#how-encryptiondecryption-works)
    - [Encryption Process (TX)](#encryption-process-tx)
    - [Decryption Process (RX)](#decryption-process-rx)
- [References](#references)

## Contents of `signing_verification/` Folder

The `signing_verification/` folder contains GNU Radio Companion (GRC) flowgraphs that demonstrate digital signing and verification using Ed25519 signatures with Nitrokey or Linux kernel keyring.

### Available Examples

#### FreeDV (Digital Voice)
- **`freedv_nitrokey_signing.grc`**: Signs FreeDV voice data using Ed25519 private key from Nitrokey slot
  - [PDF Documentation](signing_verification/freedv_nitrokey_signing.pdf)
- **`freedv_nitrokey_verification.grc`**: Verifies FreeDV voice data signatures using Ed25519 public key from Nitrokey slot
  - [PDF Documentation](signing_verification/freedv_nitrokey_verification.pdf)

#### M17 (Digital Voice Protocol)
- **`m17_nitrokey_signing.grc`**: Signs M17 voice data using Ed25519 private key from Nitrokey slot
  - [PDF Documentation](signing_verification/m17_nitrokey_signing.pdf)
- **`m17_nitrokey_verification.grc`**: Verifies M17 voice data signatures using Ed25519 public key from Nitrokey slot
  - [PDF Documentation](signing_verification/m17_nitrokey_verification.pdf)

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

FreeDV signing and verification flowgraphs demonstrate signing of digital voice data. The structure is:

### FreeDV Signing Flow

1. **Audio Input** → Resample to 8 kHz → Codec2 Encoder
2. **Codec2 frames** → Signing Block (with Nitrokey private key)
3. **Signed frames** → FreeDV Modulator → Radio Output

### FreeDV Verification Flow

1. **Radio Input** → FreeDV Demodulator
2. **Demodulated data** → Verification Block (with Nitrokey public key)
3. **Verified Codec2 frames** → Codec2 Decoder → Audio Output

Note: FreeDV signing signs individual Codec2 frames (8 bytes each for 3200 bps mode), so each frame has its own signature appended.

## M17 Signing Examples

M17 signing and verification flowgraphs follow the same pattern as FreeDV. M17 is a digital voice protocol that uses Codec2 for voice compression and 4FSK modulation.

### M17 Signing Flow

1. **Audio Input** → Resample to 8 kHz → Codec2 Encoder
2. **Codec2 frames** → Signing Block (with Nitrokey private key)
3. **Signed frames** → M17 Frame Construction → M17 Modulator → Radio Output

### M17 Verification Flow

1. **Radio Input** → M17 Demodulator
2. **Demodulated M17 frames** → Verification Block (with Nitrokey public key)
3. **Verified Codec2 frames** → Codec2 Decoder → Audio Output

Note: M17 signing signs individual Codec2 frames (8 bytes each for 2400 bps mode), similar to FreeDV. The signed frames are embedded in M17 protocol frames with sync words and frame counters. The M17 flowgraphs include placeholder modulator/demodulator blocks that can be replaced with actual M17 blocks when available.

## Adding a signature frame to the end of a transmission

The burst tagger with PTT support allows you to control when siignature frame transmissions start and end, either through hardware PTT (Push-To-Talk) signals or automatic voice activity detection. This is particularly useful for voice modes where you want to sign entire transmissions as a single unit rather than individual frames.

### How Burst Tagging Works

The burst tagger adds GNU Radio stream tags (`tx_sob` for start-of-burst and `tx_eob` for end-of-burst) to the audio stream. The signing block watches for these tags and accumulates data between `tx_sob` and `tx_eob`, then creates a single signature for the entire transmission at the end. This adds a signature frame at the end of each transmission that verifies the complete voice burst.

### Burst Tagger Python Block

Add this as an embedded Python block (`epy_block`) in your GRC flowgraph:

```python
#!/usr/bin/env python

# -*- coding: utf-8 -*-

import numpy as np

from gnuradio import gr

import pmt

class burst_tagger_ptt(gr.sync_block):

    """

    Burst tagger with PTT input support.

    Supports both voice (audio detection) and data (PTT-only) modes.

    

    When PTT is used:

    - PTT pressed (1) → tx_sob tag

    - PTT released (0) → tx_eob tag

    

    When PTT not connected (auto mode):

    - Falls back to audio energy detection

    """

    

    def __init__(self, 

                 mode='ptt',           # 'ptt', 'auto', or 'hybrid'

                 threshold_db=-40,     # Energy threshold for auto mode

                 window_size=160,      # Energy window (samples)

                 holdoff_samples=4000, # Silence duration before burst end

                 ptt_holdoff=400):     # Samples to wait after PTT release

        """

        Args:

            mode: 'ptt' = PTT only, 'auto' = audio detection only, 

                  'hybrid' = PTT starts, audio extends

            threshold_db: Energy threshold in dB (for auto/hybrid modes)

            window_size: Samples for energy averaging

            holdoff_samples: Samples of silence before auto burst end

            ptt_holdoff: Samples to wait after PTT release before tx_eob

        """

        

        # Determine input signature based on mode

        if mode == 'auto':

            # Audio only

            in_sig = [np.float32]

        else:

            # Audio + PTT

            in_sig = [np.float32, np.float32]

        

        gr.sync_block.__init__(

            self,

            name='Burst Tagger with PTT',

            in_sig=in_sig,

            out_sig=[np.float32]  # Pass through audio

        )

        

        self.mode = mode

        self.threshold_db = threshold_db

        self.threshold_linear = 10 ** (threshold_db / 20.0)

        self.window_size = window_size

        self.holdoff_samples = holdoff_samples

        self.ptt_holdoff = ptt_holdoff

        

        # State tracking

        self.in_burst = False

        self.ptt_was_active = False

        self.silence_counter = 0

        self.ptt_release_counter = 0

        self.burst_started_offset = 0

        self.window_buffer = np.zeros(window_size, dtype=np.float32)

        self.window_index = 0

        

        # Statistics

        self.burst_count = 0

        

        print(f"Burst Tagger initialized: mode={mode}, threshold={threshold_db}dB")

    

    def calculate_energy(self):

        """Calculate RMS energy of window buffer"""

        return np.sqrt(np.mean(self.window_buffer ** 2))

    

    def work(self, input_items, output_items):

        audio_in = input_items[0]

        out = output_items[0]

        

        # Get PTT input if available

        if self.mode != 'auto' and len(input_items) > 1:

            ptt_in = input_items[1]

        else:

            ptt_in = None

        

        abs_offset = self.nitems_written(0)

        

        # Process each sample

        for i in range(len(audio_in)):

            sample = audio_in[i]

            

            # Update energy calculation window

            self.window_buffer[self.window_index] = sample

            self.window_index = (self.window_index + 1) % self.window_size

            current_energy = self.calculate_energy()

            

            # Determine if we have activity

            audio_active = current_energy > self.threshold_linear

            

            if ptt_in is not None and i < len(ptt_in):

                ptt_active = ptt_in[i] > 0.5  # PTT threshold

            else:

                ptt_active = False

            

            # Mode-specific logic

            if self.mode == 'ptt':

                # PTT-only mode: strictly follow PTT

                is_active = ptt_active

                

            elif self.mode == 'auto':

                # Auto mode: audio detection only

                is_active = audio_active

                

            elif self.mode == 'hybrid':

                # Hybrid: PTT starts, audio can extend

                if ptt_active:

                    is_active = True

                elif self.in_burst:

                    # Keep burst alive if audio is active

                    is_active = audio_active

                else:

                    is_active = False

            else:

                is_active = audio_active  # Default to auto

            

            # Detect PTT transitions (rising edge)

            if ptt_in is not None and i < len(ptt_in):

                ptt_rising_edge = ptt_active and not self.ptt_was_active

                ptt_falling_edge = not ptt_active and self.ptt_was_active

                self.ptt_was_active = ptt_active

            else:

                ptt_rising_edge = False

                ptt_falling_edge = False

            

            # Start of burst detection

            if is_active or ptt_rising_edge:

                self.silence_counter = 0

                self.ptt_release_counter = 0

                

                if not self.in_burst:

                    self.in_burst = True

                    self.burst_started_offset = abs_offset + i

                    self.burst_count += 1

                    

                    # Add tx_sob tag

                    tag = gr.tag_t()

                    tag.offset = abs_offset + i

                    tag.key = pmt.intern("tx_sob")

                    tag.value = pmt.from_long(self.burst_count)

                    self.add_item_tag(0, tag)

                    

                    # Add burst_id for tracking

                    tag_id = gr.tag_t()

                    tag_id.offset = abs_offset + i

                    tag_id.key = pmt.intern("burst_id")

                    tag_id.value = pmt.from_long(self.burst_count)

                    self.add_item_tag(0, tag_id)

                    

                    energy_db = 20 * np.log10(current_energy + 1e-10)

                    mode_str = "PTT" if ptt_active else "AUDIO"

                    print(f"[{mode_str}] Burst #{self.burst_count} START at offset {abs_offset + i}, energy: {energy_db:.1f} dB")

            

            # End of burst detection

            else:

                if self.in_burst:

                    # Handle PTT release

                    if ptt_falling_edge:

                        self.ptt_release_counter = 1

                    elif self.ptt_release_counter > 0:

                        self.ptt_release_counter += 1

                    

                    # Increment silence counter for audio

                    self.silence_counter += 1

                    

                    # Determine if burst should end

                    should_end = False

                    end_reason = ""

                    

                    if self.mode == 'ptt':

                        # PTT mode: end after holdoff following PTT release

                        if self.ptt_release_counter >= self.ptt_holdoff:

                            should_end = True

                            end_reason = "PTT released"

                    

                    elif self.mode == 'auto':

                        # Auto mode: end after silence holdoff

                        if self.silence_counter >= self.holdoff_samples:

                            should_end = True

                            end_reason = "Silence timeout"

                    

                    elif self.mode == 'hybrid':

                        # Hybrid: end if both PTT released AND silence

                        ptt_ended = (self.ptt_release_counter >= self.ptt_holdoff) if ptt_in is not None else True

                        audio_ended = self.silence_counter >= self.holdoff_samples

                        

                        if ptt_ended and audio_ended:

                            should_end = True

                            end_reason = "PTT & audio ended"

                    

                    if should_end:

                        self.in_burst = False

                        

                        # Add tx_eob tag

                        tag = gr.tag_t()

                        tag.offset = abs_offset + i

                        tag.key = pmt.intern("tx_eob")

                        tag.value = pmt.from_long(self.burst_count)

                        self.add_item_tag(0, tag)

                        

                        burst_length = (abs_offset + i) - self.burst_started_offset

                        duration_sec = burst_length / 8000.0  # Assuming 8kHz

                        print(f"Burst #{self.burst_count} END at offset {abs_offset + i}")

                        print(f"  Duration: {duration_sec:.2f} sec ({burst_length} samples)")

                        print(f"  Reason: {end_reason}")

                        

                        # Reset counters

                        self.silence_counter = 0

                        self.ptt_release_counter = 0

        

        # Pass through audio

        out[:] = audio_in

        return len(out)
```

### GRC Integration with Mode Selection

Add a QT GUI Chooser block for mode selection:

**Variable Configuration:**
- **ID**: `burst_mode`
- **Label**: Burst Detection Mode
- **Type**: `string`
- **Options**: `['ptt', 'auto', 'hybrid']`
- **Labels**: `['PTT Only', 'Auto Detect', 'Hybrid']`
- **Default Value**: `'ptt'`

### Complete Flow Graph Structure

For FreeDV and M17 signing flowgraphs, integrate the burst tagger as follows:

```
┌─────────────────┐
│  Audio Source   │ (48kHz)
└────────┬────────┘
         │
┌────────▼────────┐
│  PTT Source     │ (0=RX, 1=TX)
│  (e.g., GPIO,   │
│   keyboard, or  │
│   const block)  │
└────────┬────────┘
         │
         ├─────────────────────┐
         │                     │
┌────────▼────────┐   ┌────────▼────────┐
│  Rational       │   │  PTT Signal      │
│  Resampler      │   │  (optional)     │
│  48kHz → 8kHz   │   │                 │
└────────┬────────┘   └────────┬────────┘
         │                     │
         └──────────┬──────────┘
                    │
         ┌──────────▼──────────┐
         │  Burst Tagger PTT   │ ← mode selector
         │  - Input 0: audio   │
         │  - Input 1: PTT     │
         │  - Output: tagged   │
         └──────────┬──────────┘
                    │
         ┌──────────▼──────────┐
         │  Float to Short      │
         └──────────┬──────────┘
                    │
         ┌──────────▼──────────┐
         │  Codec2 Encoder      │
         └──────────┬──────────┘
                    │
         ┌──────────▼──────────┐
         │  Modified Signer    │ ← watches tx_sob/tx_eob
         │  (accumulates &     │
         │   signs at eob)     │
         └──────────┬──────────┘
                    │
         ┌──────────▼──────────┐
         │  FreeDV/M17 Modulator│
         └──────────┬──────────┘
                    │
         ┌──────────▼──────────┐
         │  Output (File/RF)   │
         └─────────────────────┘
```

### Signature Frame at End of Transmission

When using burst tagging, the signing block accumulates all Codec2 frames between `tx_sob` and `tx_eob` tags, then creates a single Ed25519 signature for the entire transmission. This signature is appended as a signature frame at the end of the transmission. The verification block on the RX side collects all frames until it receives the signature frame, then verifies the entire burst.

**Benefits:**
- Single signature per transmission (more efficient than per-frame signing)
- Verifies complete voice burst integrity
- Prevents partial transmission verification
- Reduces signature overhead for long transmissions

#### Why Place the Signature Frame at the End?

Placing the signature frame at the end of the transmission provides important backward compatibility benefits:

**Backward Compatibility Benefits:**

- **Non-signing radios**: Would receive and decode the frames normally, simply ignore/drop the unknown signature frame at the end. Standard M17/FreeDV receivers can process the voice frames without modification, and any unrecognized frame at the end is safely discarded.

- **Signing-capable radios**: Would process M17/FreeDV frames AND verify the signature. Receivers with signature verification support can decode the voice normally while also performing cryptographic verification of the entire transmission.

- **Graceful degradation**: Communication works regardless of crypto support. This ensures that:
  - Legacy equipment continues to function
  - New signing-capable equipment can verify authenticity
  - Mixed networks (some signing, some not) operate seamlessly
  - No protocol changes required for non-signing implementations

This design follows the principle of "progressive enhancement" - adding security features without breaking existing functionality.

### Optional GPIO PTT Source Block

For hardware PTT control using GPIO (e.g., Raspberry Pi), add this as an embedded Python block:

```python
# Custom GPIO PTT source block

import numpy as np

from gnuradio import gr

class gpio_ptt_source(gr.sync_block):

    def __init__(self, gpio_pin=17, samp_rate=8000):

        gr.sync_block.__init__(

            self,

            name='GPIO PTT Source',

            in_sig=None,

            out_sig=[np.float32]

        )

        self.gpio_pin = gpio_pin

        self.samp_rate = samp_rate

        # Setup GPIO (RPi.GPIO or similar)

        try:

            import RPi.GPIO as GPIO

            GPIO.setmode(GPIO.BCM)

            GPIO.setup(self.gpio_pin, GPIO.IN, pull_up_down=GPIO.PUD_DOWN)

            self.gpio_available = True

        except ImportError:

            print("Warning: RPi.GPIO not available. Using placeholder.")

            self.gpio_available = False

        

    def read_gpio(self):

        """Read GPIO state"""

        if self.gpio_available:

            try:

                import RPi.GPIO as GPIO

                return GPIO.input(self.gpio_pin)

            except:

                return False

        return False

        

    def work(self, input_items, output_items):

        out = output_items[0]

        # Read GPIO state

        ptt_state = self.read_gpio()

        # Output 1.0 if PTT active, 0.0 if not

        out[:] = 1.0 if ptt_state else 0.0

        return len(out)
```

### Usage Examples

#### Voice Mode with PTT

```python
burst_mode = 'ptt'
# PTT press → tx_sob immediately
# PTT release → wait 400 samples → tx_eob
# Good for: Voice, repeater commands
```

#### Data Mode (no PTT)

```python
burst_mode = 'auto'
# Detects start/end of data packets by energy
# Good for: APRS, packet radio, autonomous systems
```

#### Hybrid Mode (PTT + VOX)

```python
burst_mode = 'hybrid'
# PTT starts transmission
# Audio energy keeps it alive
# Ends when BOTH PTT released AND audio stops
# Good for: Voice with "tail" for turnaround time
```

### Testing Configuration

Add these debugging blocks to your flowgraph:

1. **Tag Debug Block**: Add `blocks_tag_debug` after the burst tagger to display `tx_sob`, `tx_eob`, and `burst_id` tags
2. **QT GUI Time Sink**: Add `qtgui_time_sink_f` to visualize tagged regions in the audio stream

**Tag Debug Configuration:**
- **Key**: `tx_sob` (or `tx_eob`, `burst_id`)
- **Display**: Console output showing tag values and offsets

### Parameters for Different Use Cases

#### Voice (PTT)

```python
mode = 'ptt'
ptt_holdoff = 400  # 50ms at 8kHz (tail after PTT release)
threshold_db = -40  # (unused in PTT mode)
holdoff_samples = 4000  # (unused in PTT mode)
```

#### Voice (VOX)

```python
mode = 'auto'
threshold_db = -35
holdoff_samples = 8000  # 1 second silence
ptt_holdoff = 400  # (unused in auto mode)
```

#### Data Packets

```python
mode = 'auto'
threshold_db = -50  # More sensitive
holdoff_samples = 800  # 100ms gap detection
ptt_holdoff = 400  # (unused in auto mode)
```

#### Repeater Commands

```python
mode = 'ptt'
ptt_holdoff = 80  # 10ms tail
# Fast response, PTT-controlled
```

### Modifying Signing Blocks for Burst Tagging

To use burst tagging with the existing signing blocks, modify the signing `epy_block` to:

1. Watch for `tx_sob` and `tx_eob` tags
2. Accumulate Codec2 frames between tags
3. Sign the accumulated data when `tx_eob` is received
4. Output the accumulated frames followed by the signature frame

**Example modification to signing block:**

```python
def work(self, input_items, output_items):
    # Get tags
    tags = self.get_tags_in_window(0, 0, len(input_items[0]))
    
    for tag in tags:
        if pmt.to_python(tag.key) == 'tx_sob':
            # Start accumulating
            self._accumulated_data = bytearray()
        elif pmt.to_python(tag.key) == 'tx_eob':
            # Sign accumulated data
            if len(self._accumulated_data) > 0:
                signature = nacl.sign_ed25519(
                    bytes(self._accumulated_data), 
                    private_key
                )
                # Output accumulated data + signature
                signed_burst = bytes(self._accumulated_data) + signature
                # ... output signed_burst ...
                self._accumulated_data = bytearray()
    
    # Accumulate current frame data
    # ... process input_items ...
```

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

**For FreeDV:**
- FreeDV demodulator is already included in verification flowgraphs
- Ensure FreeDV mode matches TX side (e.g., MODE_1600, MODE_700)

**For M17:**
- M17 demodulator placeholder is included in verification flowgraphs
- M17 uses 4FSK modulation at 4800 symbols/sec
- Replace placeholder demodulator with actual M17 demodulator block when available
- Ensure M17 frame structure matches TX side

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

## Encryption/Decryption Examples

The `encrypt_decrypt/` folder contains GNU Radio Companion (GRC) flowgraphs that demonstrate encryption and decryption using ChaCha20-Poly1305 authenticated encryption with Nitrokey.

### Available Examples

#### FreeDV (Digital Voice Encryption)
- **`freedv_nitrokey_encryption.grc`**: Encrypts FreeDV voice data using ChaCha20-Poly1305 with key from Nitrokey slot
- **`freedv_nitrokey_decryption.grc`**: Decrypts FreeDV voice data using ChaCha20-Poly1305 with key from Nitrokey slot

### How Encryption/Decryption Works

#### Encryption Process (TX)
1. Audio input is resampled to 8 kHz
2. Codec2 encoder compresses voice data
3. ChaCha20-Poly1305 encryption key is loaded from Nitrokey slot
4. Codec2 frames are encrypted using ChaCha20-Poly1305 (includes authentication tag)
5. Encrypted frames are modulated with FreeDV and transmitted

#### Decryption Process (RX)
1. Encrypted frames are received and demodulated with FreeDV
2. ChaCha20-Poly1305 decryption key is loaded from Nitrokey slot
3. Encrypted frames are decrypted (includes authentication verification)
4. Decrypted Codec2 frames are decoded
5. Audio output is resampled and played

**Note**: Encryption/decryption examples use nonce counters that must be synchronized between TX and RX. The nonce counter increments for each frame and must start at the same value on both sides.

## References

- Ed25519: High-speed high-security signatures (RFC 8032)
- gr-nacl: GNU Radio module for modern cryptography
- FreeDV: Open source digital voice mode
- M17: Digital voice protocol for amateur radio
- ChaCha20-Poly1305: Authenticated encryption (RFC 8439)

