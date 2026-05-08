# SPDX-License-Identifier: GPL-3.0-or-later

function(gr_linux_crypto4_add_ut name)
  add_executable(${name} ${name}.cpp)
  target_link_libraries(
    ${name}
    PRIVATE gnuradio4::gnuradio-options
            gnuradio4::gnuradio-core
            gnuradio4::gnuradio-blocklib-core
            gnuradio4::gr-linux-crypto
            ut)
  add_test(NAME ${name} COMMAND ${CMAKE_CROSSCOMPILING_EMULATOR} $<TARGET_FILE:${name}>)
endfunction()

gr_linux_crypto4_add_ut(qa_KernelCryptoAes)
gr_linux_crypto4_add_ut(qa_KernelKeyringSource)
gr_linux_crypto4_add_ut(qa_NitrokeyInterface)
gr_linux_crypto4_add_ut(qa_BrainpoolEcdsaSign)
gr_linux_crypto4_add_ut(qa_BrainpoolEcdsaVerify)
gr_linux_crypto4_add_ut(qa_BrainpoolEciesEncrypt)
gr_linux_crypto4_add_ut(qa_BrainpoolEciesDecrypt)
gr_linux_crypto4_add_ut(qa_BrainpoolEciesMultiEncrypt)
gr_linux_crypto4_add_ut(qa_BrainpoolEciesMultiDecrypt)
