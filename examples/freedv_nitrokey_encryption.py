#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#
# SPDX-License-Identifier: GPL-3.0
#
# GNU Radio Python Flow Graph
# Title: FreeDV Encryption with Nitrokey
# Author: gr-linux-crypto
# Copyright: Copyright 2024
# Description: FreeDV voice encryption using Nitrokey + gr-nacl ChaCha20-Poly1305. Encrypts Codec2 compressed voice data before FreeDV modulation.
# GNU Radio version: 3.10.9.2

import signal
import sys

import freedv_nitrokey_encryption_epy_block_0 as epy_block_0  # embedded python block
from gnuradio import (
    audio,
    blocks,
    filter,
    gr,
    linux_crypto,
    qtgui,
    vocoder,
)
from gnuradio.vocoder import codec2, freedv_api
from PyQt5 import Qt


class freedv_nitrokey_encryption(gr.top_block, Qt.QWidget):

    def __init__(self):
        gr.top_block.__init__(
            self, "FreeDV Encryption with Nitrokey", catch_exceptions=True
        )
        Qt.QWidget.__init__(self)
        self.setWindowTitle("FreeDV Encryption with Nitrokey")
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

        self.settings = Qt.QSettings("GNU Radio", "freedv_nitrokey_encryption")

        try:
            geometry = self.settings.value("geometry")
            if geometry:
                self.restoreGeometry(geometry)
        except BaseException as exc:
            print(f"Qt GUI: Could not restore geometry: {str(exc)}", file=sys.stderr)

        ##################################################
        # Variables
        ##################################################
        # self.samp_rate = _samp_rate = 8000
        self.nitrokey_slot = nitrokey_slot = 1
        # self.freedv_mode = _freedv_mode = "MODE_1600"

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
        self.vocoder_freedv_tx_ss_0 = vocoder.freedv_tx_ss(
            freedv_api.MODE_1600, "Encrypted FreeDV", 1
        )
        self.vocoder_codec2_encode_sp_0 = vocoder.codec2_encode_sp(codec2.MODE_2400)
        self.rational_resampler_xxx_0 = filter.rational_resampler_fff(
            interpolation=1, decimation=6, taps=[], fractional_bw=0
        )
        self.linux_crypto_nitrokey_interface_0 = linux_crypto.nitrokey_interface(
            nitrokey_slot, False
        )
        self._freedv_mode_tool_bar = Qt.QToolBar(self)
        self._freedv_mode_tool_bar.addWidget(Qt.QLabel("FreeDV Mode" + ": "))
        self._freedv_mode_line_edit = Qt.QLineEdit(str(self.freedv_mode))
        self._freedv_mode_tool_bar.addWidget(self._freedv_mode_line_edit)
        self._freedv_mode_line_edit.editingFinished.connect(
            lambda: self.set_freedv_mode(str(str(self._freedv_mode_line_edit.text())))
        )
        self.top_grid_layout.addWidget(self._freedv_mode_tool_bar, 3, 0, 1, 1)
        for r in range(3, 4):
            self.top_grid_layout.setRowStretch(r, 1)
        for c in range(0, 1):
            self.top_grid_layout.setColumnStretch(c, 1)
        self.epy_block_0 = epy_block_0.blk()
        self.blocks_float_to_short_0 = blocks.float_to_short(1, 32768)
        self.blocks_file_sink_0 = blocks.file_sink(
            gr.sizeof_short * 1, "/tmp/freedv_encrypted.bin", False
        )
        self.blocks_file_sink_0.set_unbuffered(False)
        self.blocks_char_to_short_0 = blocks.char_to_short(1)
        self.audio_source_0 = audio.source(48000, "", True)

        ##################################################
        # Connections
        ##################################################
        self.connect((self.audio_source_0, 0), (self.rational_resampler_xxx_0, 0))
        self.connect((self.blocks_char_to_short_0, 0), (self.vocoder_freedv_tx_ss_0, 0))
        self.connect(
            (self.blocks_float_to_short_0, 0), (self.vocoder_codec2_encode_sp_0, 0)
        )
        self.connect((self.epy_block_0, 0), (self.blocks_char_to_short_0, 0))
        self.connect((self.linux_crypto_nitrokey_interface_0, 0), (self.epy_block_0, 1))
        self.connect(
            (self.rational_resampler_xxx_0, 0), (self.blocks_float_to_short_0, 0)
        )
        self.connect((self.vocoder_codec2_encode_sp_0, 0), (self.epy_block_0, 0))
        self.connect((self.vocoder_freedv_tx_ss_0, 0), (self.blocks_file_sink_0, 0))

    def closeEvent(self, event):
        self.settings = Qt.QSettings("GNU Radio", "freedv_nitrokey_encryption")
        self.settings.setValue("geometry", self.saveGeometry())
        self.stop()
        self.wait()

        event.accept()

    def get_samp_rate(self):
        return self.samp_rate

    def set_samp_rate(self, samp_rate):
        self.samp_rate = samp_rate

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

    def get_freedv_mode(self):
        return self.freedv_mode

    def set_freedv_mode(self, freedv_mode):
        self.freedv_mode = freedv_mode
        Qt.QMetaObject.invokeMethod(
            self._freedv_mode_line_edit,
            "setText",
            Qt.Q_ARG("QString", str(self.freedv_mode)),
        )


def main(top_block_cls=freedv_nitrokey_encryption, options=None):

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
