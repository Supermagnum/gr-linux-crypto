import numpy as np
from gnuradio import gr

try:
    from gnuradio import nacl

    NACL_AVAILABLE = True
except ImportError:
    NACL_AVAILABLE = False
    print("Warning: gr-nacl not available. Decryption will not work.")

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
            name="FreeDV Voice Decryptor",
            in_sig=[np.uint8, np.uint8],
            out_sig=[(np.uint8, 48)],
        )
        self._encrypted_buffer = bytearray()
        self._key_buffer = bytearray()
        self._nonce_counter = 0
        self._nonce_length = 12  # 96 bits for ChaCha20-Poly1305
        self._frame_size_with_tag = 8 + 16  # Codec2 frame (8) + Poly1305 tag (16)

    def work(self, input_items, output_items):
        encrypted_in = input_items[0]
        key_in = input_items[1]

        # Collect encrypted Codec2 data
        if len(encrypted_in) > 0:
            self._encrypted_buffer.extend(encrypted_in.tolist())

        # Collect key from Nitrokey (need 32 bytes for ChaCha20)
        if len(key_in) > 0:
            self._key_buffer.extend(key_in.tolist())

        out_len = min(len(output_items[0]), len(encrypted_in))

        # Decrypt when we have enough data
        if (
            len(self._encrypted_buffer) >= self._frame_size_with_tag
            and len(self._key_buffer) >= 32
        ):
            try:
                # Get encrypted frame (Codec2 frame + auth tag)
                encrypted_frame = bytes(
                    self._encrypted_buffer[: self._frame_size_with_tag]
                )
                self._encrypted_buffer = self._encrypted_buffer[
                    self._frame_size_with_tag :
                ]

                # Get decryption key (32 bytes for ChaCha20)
                key = bytes(self._key_buffer[:32])

                # Generate nonce (12 bytes, incrementing counter - must match encryption)
                nonce = self._nonce_counter.to_bytes(
                    self._nonce_length, byteorder="little"
                )
                self._nonce_counter = (self._nonce_counter + 1) % (2**96)

                # Decrypt Codec2 frame
                if CRYPTOGRAPHY_AVAILABLE:
                    cipher = ChaCha20Poly1305(key)
                    try:
                        decrypted_frame = cipher.decrypt(nonce, encrypted_frame, None)
                    except Exception as e:
                        print(f"Decryption failed: {e}")
                        decrypted_frame = b"\x00" * 8  # Silent frame on error
                elif NACL_AVAILABLE:
                    # Try gr-nacl if available
                    try:
                        decrypted_frame = nacl.decrypt_chacha20_poly1305(
                            encrypted_frame, key, nonce
                        )
                    except AttributeError:
                        decrypted_frame = encrypted_frame[:8]  # Fallback: no decryption
                else:
                    decrypted_frame = encrypted_frame[:8]  # No decryption available

                # Output decrypted Codec2 frame
                if len(decrypted_frame) <= len(output_items[0]):
                    out_data = np.frombuffer(decrypted_frame[:out_len], dtype=np.uint8)
                    if len(out_data) <= len(output_items[0]):
                        output_items[0][: len(out_data)] = out_data
                    return len(out_data)
            except Exception as e:
                print(f"Decryption error: {e}")
                import traceback

                traceback.print_exc()

        # No data to output yet
        return 0
