import numpy as np
from gnuradio import gr

try:
    from gnuradio import nacl

    NACL_AVAILABLE = True
except ImportError:
    NACL_AVAILABLE = False
    print("Warning: gr-nacl not available. Verification will not work.")


class blk(gr.sync_block):
    def __init__(self):
        gr.sync_block.__init__(
            self,
            name="FreeDV Voice Verifier",
            in_sig=[np.uint8, np.uint8],
            out_sig=[(np.uint8, 48)],
        )
        self._signed_buffer = bytearray()
        self._key_buffer = bytearray()
        self._signature_length = 64  # Ed25519 signature is 64 bytes
        self._frame_size_with_signature = (
            8 + 64
        )  # Codec2 frame (8) + signature (64) = 72 bytes

    def work(self, input_items, output_items):
        signed_in = input_items[0]
        key_in = input_items[1]

        # Collect signed Codec2 data
        if len(signed_in) > 0:
            self._signed_buffer.extend(signed_in.tolist())

        # Collect key data from Nitrokey (need 32 bytes for Ed25519)
        if len(key_in) > 0:
            self._key_buffer.extend(key_in.tolist())

        out_len = min(len(output_items[0]), 48)

        # Verify when we have complete signed frame
        if (
            len(self._signed_buffer) >= self._frame_size_with_signature
            and len(self._key_buffer) >= 32
        ):
            try:
                # Get signed frame (8 bytes Codec2 + 64 bytes signature)
                signed_frame = bytes(
                    self._signed_buffer[: self._frame_size_with_signature]
                )
                self._signed_buffer = self._signed_buffer[
                    self._frame_size_with_signature :
                ]

                # Extract Codec2 frame and signature
                codec2_frame = signed_frame[:8]
                signature = signed_frame[8:]

                # Get public key (32 bytes for Ed25519)
                public_key = bytes(self._key_buffer[:32])

                if NACL_AVAILABLE and len(public_key) == 32 and len(signature) == 64:
                    # Verify Ed25519 signature using gr-nacl
                    try:
                        is_valid = nacl.verify_ed25519(
                            codec2_frame, signature, public_key
                        )
                        if is_valid:
                            # Output verified Codec2 frame
                            out_data = np.frombuffer(
                                codec2_frame[:out_len], dtype=np.uint8
                            )
                            if len(out_data) <= len(output_items[0]):
                                output_items[0][: len(out_data)] = out_data
                                return len(out_data)
                        else:
                            print("FAILED: FreeDV Codec2 frame signature is INVALID")
                            # Output silent frame on verification failure
                            silent_frame = b"\x00" * 8
                            out_data = np.frombuffer(
                                silent_frame[:out_len], dtype=np.uint8
                            )
                            if len(out_data) <= len(output_items[0]):
                                output_items[0][: len(out_data)] = out_data
                                return len(out_data)
                    except AttributeError:
                        print(
                            "Warning: gr-nacl verify_ed25519 not found. Cannot verify."
                        )
                        # Pass through without verification
                        out_data = np.frombuffer(codec2_frame[:out_len], dtype=np.uint8)
                        if len(out_data) <= len(output_items[0]):
                            output_items[0][: len(out_data)] = out_data
                            return len(out_data)
                else:
                    print(
                        "Warning: Verification not available - missing key or signature"
                    )
                    # Pass through without verification
                    out_data = np.frombuffer(codec2_frame[:out_len], dtype=np.uint8)
                    if len(out_data) <= len(output_items[0]):
                        output_items[0][: len(out_data)] = out_data
                        return len(out_data)
            except Exception as e:
                print(f"Verification error: {e}")
                import traceback

                traceback.print_exc()
                # Output silent frame on error
                silent_frame = b"\x00" * 8
                out_data = np.frombuffer(silent_frame[:out_len], dtype=np.uint8)
                if len(out_data) <= len(output_items[0]):
                    output_items[0][: len(out_data)] = out_data
                    return len(out_data)

        # No data to output yet
        return 0
