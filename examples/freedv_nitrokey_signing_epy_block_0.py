import numpy as np
from gnuradio import gr

try:
    from gnuradio import nacl

    NACL_AVAILABLE = True
except ImportError:
    NACL_AVAILABLE = False
    print("Warning: gr-nacl not available. Signing will not work.")


class blk(gr.sync_block):
    def __init__(self):
        gr.sync_block.__init__(
            self,
            name="FreeDV Voice Signer",
            in_sig=[(np.uint8, 48), np.uint8],
            out_sig=[np.uint8],
        )
        self._codec2_buffer = bytearray()
        self._key_buffer = bytearray()
        self._signature_length = 64  # Ed25519 signature is 64 bytes

    def work(self, input_items, output_items):
        codec2_in = input_items[0]
        key_in = input_items[1]

        # Collect Codec2 compressed voice data
        if len(codec2_in) > 0:
            self._codec2_buffer.extend(codec2_in.tolist())

        # Collect key data from Nitrokey (need 32 bytes for Ed25519)
        if len(key_in) > 0:
            self._key_buffer.extend(key_in.tolist())

        out_len = min(len(output_items[0]), len(codec2_in))

        # Sign Codec2 frames (typically 8 bytes for 3200 bps mode)
        if len(self._codec2_buffer) >= 8 and len(self._key_buffer) >= 32:
            try:
                # Get Codec2 frame (8 bytes)
                codec2_frame = bytes(self._codec2_buffer[:8])
                self._codec2_buffer = self._codec2_buffer[8:]

                # Get private key (32 bytes for Ed25519)
                private_key = bytes(self._key_buffer[:32])

                if NACL_AVAILABLE and len(private_key) == 32:
                    # Create Ed25519 signature using gr-nacl
                    try:
                        signature = nacl.sign_ed25519(codec2_frame, private_key)
                    except AttributeError:
                        print(
                            "Warning: gr-nacl sign_ed25519 not found. Using placeholder."
                        )
                        signature = b"\x00" * 64

                    # Append signature to Codec2 frame
                    signed_frame = codec2_frame + signature

                    # Output signed frame (8 bytes Codec2 + 64 bytes signature = 72 bytes total)
                    out_data = np.frombuffer(signed_frame[:out_len], dtype=np.uint8)
                    if len(out_data) <= len(output_items[0]):
                        output_items[0][: len(out_data)] = out_data
                    return len(out_data)
                else:
                    # No signing available, just pass Codec2 frame
                    out_data = np.frombuffer(codec2_frame[:out_len], dtype=np.uint8)
                    if len(out_data) <= len(output_items[0]):
                        output_items[0][: len(out_data)] = out_data
                    return len(out_data)
            except Exception as e:
                print(f"Signing error: {e}")
                import traceback

                traceback.print_exc()

        # No data to output yet
        return 0
