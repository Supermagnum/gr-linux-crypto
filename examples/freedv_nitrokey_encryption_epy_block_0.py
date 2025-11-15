import numpy as np
from gnuradio import gr

try:
    from gnuradio import nacl

    NACL_AVAILABLE = True
except ImportError:
    NACL_AVAILABLE = False
    print("Warning: gr-nacl not available. Encryption will not work.")

try:
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False
    print("Warning: cryptography library not available. Using fallback.")


class blk(gr.sync_block):
    def __init__(self):
        gr.sync_block.__init__(
            self,
            name="FreeDV Voice Encryptor",
            in_sig=[(np.uint8, 48), np.uint8],
            out_sig=[np.uint8],
        )
        self._codec2_buffer = bytearray()
        self._key_buffer = bytearray()
        self._nonce_counter = 0
        self._nonce_length = 12  # 96 bits for ChaCha20-Poly1305

    def work(self, input_items, output_items):
        codec2_in = input_items[0]
        key_in = input_items[1]

        # Collect Codec2 compressed voice data
        if len(codec2_in) > 0:
            self._codec2_buffer.extend(codec2_in.tolist())

        # Collect key from Nitrokey (need 32 bytes for ChaCha20)
        if len(key_in) > 0:
            self._key_buffer.extend(key_in.tolist())

        out_len = min(len(output_items[0]), len(codec2_in))

        # Encrypt when we have enough data
        if len(self._codec2_buffer) >= 8 and len(self._key_buffer) >= 32:
            try:
                # Get Codec2 frame (typically 8 bytes for 3200 bps mode)
                frame_size = min(8, len(self._codec2_buffer))
                codec2_frame = bytes(self._codec2_buffer[:frame_size])
                self._codec2_buffer = self._codec2_buffer[frame_size:]

                # Get encryption key (32 bytes for ChaCha20)
                key = bytes(self._key_buffer[:32])

                # Generate nonce (12 bytes, incrementing counter)
                nonce = self._nonce_counter.to_bytes(
                    self._nonce_length, byteorder="little"
                )
                self._nonce_counter = (self._nonce_counter + 1) % (2**96)

                # Encrypt Codec2 frame
                if CRYPTOGRAPHY_AVAILABLE:
                    cipher = ChaCha20Poly1305(key)
                    encrypted_frame = cipher.encrypt(nonce, codec2_frame, None)
                elif NACL_AVAILABLE:
                    # Try gr-nacl if available
                    try:
                        encrypted_frame = nacl.encrypt_chacha20_poly1305(
                            codec2_frame, key, nonce
                        )
                    except AttributeError:
                        encrypted_frame = codec2_frame  # Fallback: no encryption
                else:
                    encrypted_frame = codec2_frame  # No encryption available

                # Output encrypted frame
                if len(encrypted_frame) <= len(output_items[0]):
                    out_data = np.frombuffer(encrypted_frame[:out_len], dtype=np.uint8)
                    if len(out_data) <= len(output_items[0]):
                        output_items[0][: len(out_data)] = out_data
                return len(out_data)
            except Exception as e:
                print(f"Encryption error: {e}")
                import traceback

                traceback.print_exc()

        # No data to output yet
        return 0
