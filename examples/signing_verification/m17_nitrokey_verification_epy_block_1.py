import numpy as np
from gnuradio import gr


class blk(gr.sync_block):
    def __init__(self):
        gr.sync_block.__init__(
            self, name="M17 Demodulator", in_sig=[np.short], out_sig=[np.uint8]
        )
        # M17 uses 4FSK demodulation
        # For simplicity, this is a placeholder that passes through
        # In a real implementation, this would do M17 4FSK demodulation

    def work(self, input_items, output_items):
        in_data = input_items[0]
        min(len(output_items[0]), len(in_data))

        # Simple pass-through (actual M17 demodulation would go here)
        # M17 uses 4FSK: 4 frequencies map to symbols
        # This is a placeholder - real M17 demodulator would do:
        # 1. Detect 4FSK frequencies
        # 2. Map frequencies to symbols (2 bits per symbol)
        # 3. Convert symbols to bytes

        # For now, just convert short to bytes
        out_data = (in_data.astype(np.int32) + 128).astype(np.uint8)
        if len(out_data) <= len(output_items[0]):
            output_items[0][: len(out_data)] = out_data
            return len(out_data)

        return 0
