import struct

import numpy as np
from gnuradio import gr

try:
    from gnuradio import nacl

    NACL_AVAILABLE = True
except ImportError:
    NACL_AVAILABLE = False
    print("Warning: gr-nacl not available. Signing will not work.")

try:
    from python.m17_frame import M17Frame

    M17_AVAILABLE = True
except ImportError:
    try:
        from m17_frame import M17Frame

        M17_AVAILABLE = True
    except ImportError:
        M17_AVAILABLE = False
        print("Warning: M17 frame module not available.")


class blk(gr.sync_block):
    def __init__(self):
        gr.sync_block.__init__(
            self,
            name="M17 Voice Signer",
            in_sig=[(np.uint8, 48), np.uint8],
            out_sig=[np.uint8],
        )
        self._codec2_buffer = bytearray()
        self._key_buffer = bytearray()
        self._signature_length = 64  # Ed25519 signature is 64 bytes
        self._frame_counter = 0

    def work(self, input_items, output_items):
        codec2_in = input_items[0]
        key_in = input_items[1]

        # Collect Codec2 compressed voice data
        if len(codec2_in) > 0:
            self._codec2_buffer.extend(codec2_in.tolist())

        # Collect key data from Nitrokey (need 32 bytes for Ed25519)
        if len(key_in) > 0:
            self._key_buffer.extend(key_in.tolist())

        out_len = min(len(output_items[0]), len(codec2_in) * 10)

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
                    signed_codec2 = codec2_frame + signature

                    # Create M17 stream frame with signed payload
                    # M17 stream frame: sync word (2) + payload (16) + frame counter (2) = 20 bytes
                    # We'll embed the signed data in the payload
                    if M17_AVAILABLE:
                        # Use M17Frame class to create frame
                        m17_frame = M17Frame.create_stream_frame(
                            payload=signed_codec2[:16],  # M17 payload is 16 bytes
                            frame_counter=self._frame_counter,
                        )
                        self._frame_counter = (self._frame_counter + 1) % 65536
                        frame_bytes = m17_frame.to_bytes()
                    else:
                        # Fallback: simple M17 frame structure
                        # M17 stream frame: sync (0xFF5D) + payload (16) + counter (2)
                        sync_word = struct.pack(">H", 0xFF5D)  # M17 stream sync
                        frame_counter_bytes = struct.pack(">H", self._frame_counter)[:2]
                        self._frame_counter = (self._frame_counter + 1) % 65536
                        # Pad signed_codec2 to 16 bytes for M17 payload
                        payload = signed_codec2[:16].ljust(16, b"\x00")
                        frame_bytes = sync_word + payload + frame_counter_bytes

                    # Output M17 frame bytes
                    out_data = np.frombuffer(frame_bytes[:out_len], dtype=np.uint8)
                    if len(out_data) <= len(output_items[0]):
                        output_items[0][: len(out_data)] = out_data
                        return len(out_data)
                else:
                    # No signing available, just pass Codec2 frame in M17 format
                    if M17_AVAILABLE:
                        m17_frame = M17Frame.create_stream_frame(
                            payload=codec2_frame[:16].ljust(16, b"\x00"),
                            frame_counter=self._frame_counter,
                        )
                        self._frame_counter = (self._frame_counter + 1) % 65536
                        frame_bytes = m17_frame.to_bytes()
                    else:
                        sync_word = struct.pack(">H", 0xFF5D)
                        frame_counter_bytes = struct.pack(">H", self._frame_counter)[:2]
                        self._frame_counter = (self._frame_counter + 1) % 65536
                        payload = codec2_frame[:16].ljust(16, b"\x00")
                        frame_bytes = sync_word + payload + frame_counter_bytes

                    out_data = np.frombuffer(frame_bytes[:out_len], dtype=np.uint8)
                    if len(out_data) <= len(output_items[0]):
                        output_items[0][: len(out_data)] = out_data
                        return len(out_data)
            except Exception as e:
                print(f"Signing error: {e}")
                import traceback

                traceback.print_exc()

        # No data to output yet
        return 0
