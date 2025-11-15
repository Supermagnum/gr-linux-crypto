#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#
# SPDX-License-Identifier: GPL-3.0
#
# GNU Radio Python Flow Graph
# Title: M17 Verification with Nitrokey
# Author: gr-linux-crypto
# Copyright: Copyright 2024
# Description: M17 voice signature verification using gr-nacl Ed25519. Verifies signatures embedded in M17 Codec2 frames after demodulation.
# GNU Radio version: 3.10.9.2

import signal
import sys

import m17_nitrokey_verification_epy_block_0 as epy_block_0  # embedded python block
import m17_nitrokey_verification_epy_block_1 as epy_block_1  # embedded python block
import m17_nitrokey_verification_epy_block_2 as epy_block_2  # embedded python block
import pmt
from gnuradio import (
    audio,
    blocks,
    filter,
    gr,
    linux_crypto,
    qtgui,
    vocoder,
)
from gnuradio.vocoder import codec2
from PyQt5 import Qt


class m17_nitrokey_verification(gr.top_block, Qt.QWidget):

    def __init__(self):
        gr.top_block.__init__(
            self, "M17 Verification with Nitrokey", catch_exceptions=True
        )
        Qt.QWidget.__init__(self)
        self.setWindowTitle("M17 Verification with Nitrokey")
        qtgui.util.check_set_qss()
        try:
            self.setWindowIcon(Qt.QIcon.fromTheme("gnuradio-grc"))
        except BaseException as exc:
            print(f"Qt GUI: Could not set Icon: {str(exc)}", file=sys.stderr)
        self.top_scroll_layout = Qt.QVBoxLayout()
        self.setLayout(self.top_scroll_layout)
        self.top_scroll = Qt.QScrollArea()
        self.top_scroll.setFrameStyle(Qt.QFrame.NoFrame)
        self.top_scroll_layout.addWidget(self.top_scroll)
        self.top_scroll.setWidgetResizable(True)
        self.top_widget = Qt.QWidget()
        self.top_scroll.setWidget(self.top_widget)
        self.top_layout = Qt.QVBoxLayout(self.top_widget)
        self.top_grid_layout = Qt.QGridLayout()
        self.top_layout.addLayout(self.top_grid_layout)

        self.settings = Qt.QSettings("GNU Radio", "m17_nitrokey_verification")

        try:
            geometry = self.settings.value("geometry")
            if geometry:
                self.restoreGeometry(geometry)
        except BaseException as exc:
            print(f"Qt GUI: Could not restore geometry: {str(exc)}", file=sys.stderr)

        ##################################################
        # Variables
        ##################################################
        self.samp_rate = samp_rate = 8000
        self.nitrokey_slot = nitrokey_slot = 1
        self.authenticate_button = False  # Available but not used in this example

        ##################################################
        # Blocks
        ##################################################

        self._nitrokey_slot_tool_bar = Qt.QToolBar(self)
        self._nitrokey_slot_tool_bar.addWidget(Qt.QLabel("Nitrokey Slot" + ": "))
        self._nitrokey_slot_line_edit = Qt.QLineEdit(str(self.nitrokey_slot))
        self._nitrokey_slot_tool_bar.addWidget(self._nitrokey_slot_line_edit)
        self._nitrokey_slot_line_edit.editingFinished.connect(
            lambda: self.set_nitrokey_slot(
                int(str(self._nitrokey_slot_line_edit.text()))
            )
        )
        self.top_grid_layout.addWidget(self._nitrokey_slot_tool_bar, 1, 0, 1, 1)
        for r in range(1, 2):
            self.top_grid_layout.setRowStretch(r, 1)
        for c in range(0, 1):
            self.top_grid_layout.setColumnStretch(c, 1)
        self.vocoder_codec2_decode_ps_0 = vocoder.codec2_decode_ps(codec2.MODE_2400)
        self.rational_resampler_xxx_1 = filter.rational_resampler_fff(
            interpolation=6, decimation=1, taps=[], fractional_bw=0
        )
        self.linux_crypto_nitrokey_interface_0 = linux_crypto.nitrokey_interface(
            nitrokey_slot, False
        )
        self.epy_block_2 = epy_block_2.blk()
        self.epy_block_1 = epy_block_1.blk()
        self.epy_block_0 = epy_block_0.blk()
        self.blocks_throttle2_0 = blocks.throttle(
            gr.sizeof_short * 1,
            samp_rate,
            True,
            (
                0
                if "auto" == "auto"
                else max(
                    int(float(0.1) * samp_rate) if "auto" == "time" else int(0.1), 1
                )
            ),
        )
        self.blocks_short_to_float_0 = blocks.short_to_float(1, 32768)
        self.blocks_file_source_0 = blocks.file_source(
            gr.sizeof_short * 1, "/tmp/m17_signed.bin", False, 0, 0
        )
        self.blocks_file_source_0.set_begin_tag(pmt.PMT_NIL)
        _authenticate_button_push_button = Qt.QPushButton("Authenticate Nitrokey")
        _authenticate_button_push_button = Qt.QPushButton("Authenticate Nitrokey")
        self._authenticate_button_choices = {"Pressed": 1, "Released": 0}
        _authenticate_button_push_button.pressed.connect(
            lambda: self.set_authenticate_button(
                self._authenticate_button_choices["Pressed"]
            )
        )
        _authenticate_button_push_button.released.connect(
            lambda: self.set_authenticate_button(
                self._authenticate_button_choices["Released"]
            )
        )
        self.top_layout.addWidget(_authenticate_button_push_button)
        self.audio_sink_0 = audio.sink(48000, "", True)

        ##################################################
        # Connections
        ##################################################
        self.connect((self.blocks_file_source_0, 0), (self.blocks_throttle2_0, 0))
        self.connect(
            (self.blocks_short_to_float_0, 0), (self.rational_resampler_xxx_1, 0)
        )
        self.connect((self.blocks_throttle2_0, 0), (self.epy_block_1, 0))
        self.connect((self.epy_block_0, 0), (self.vocoder_codec2_decode_ps_0, 0))
        self.connect((self.epy_block_1, 0), (self.epy_block_0, 0))
        self.connect((self.linux_crypto_nitrokey_interface_0, 0), (self.epy_block_0, 1))
        self.connect((self.rational_resampler_xxx_1, 0), (self.audio_sink_0, 0))
        self.connect(
            (self.vocoder_codec2_decode_ps_0, 0), (self.blocks_short_to_float_0, 0)
        )

    def closeEvent(self, event):
        self.settings = Qt.QSettings("GNU Radio", "m17_nitrokey_verification")
        self.settings.setValue("geometry", self.saveGeometry())
        self.stop()
        self.wait()

        event.accept()

    def get_samp_rate(self):
        return self.samp_rate

    def set_samp_rate(self, samp_rate):
        self.samp_rate = samp_rate
        self.blocks_throttle2_0.set_sample_rate(self.samp_rate)

    def get_nitrokey_slot(self):
        return self.nitrokey_slot

    def set_nitrokey_slot(self, nitrokey_slot):
        self.nitrokey_slot = nitrokey_slot
        Qt.QMetaObject.invokeMethod(
            self._nitrokey_slot_line_edit,
            "setText",
            Qt.Q_ARG("QString", str(self.nitrokey_slot)),
        )
        self.linux_crypto_nitrokey_interface_0.set_slot(self.nitrokey_slot)

    def get_authenticate_button(self):
        return self.authenticate_button

    def set_authenticate_button(self, authenticate_button):
        self.authenticate_button = authenticate_button


def main(top_block_cls=m17_nitrokey_verification, options=None):

    qapp = Qt.QApplication(sys.argv)

    tb = top_block_cls()

    tb.start()

    tb.show()

    def sig_handler(sig=None, frame=None):
        tb.stop()
        tb.wait()

        Qt.QApplication.quit()

    signal.signal(signal.SIGINT, sig_handler)
    signal.signal(signal.SIGTERM, sig_handler)

    timer = Qt.QTimer()
    timer.start(500)
    timer.timeout.connect(lambda: None)

    qapp.exec_()


if __name__ == "__main__":
    main()
