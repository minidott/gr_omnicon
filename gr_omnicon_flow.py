#!/usr/bin/env python2
# -*- coding: utf-8 -*-
##################################################
# GNU Radio Python Flow Graph
# Title: gr_omnicon
# Generated: Tue Jan 19 21:03:09 2016
##################################################

from gnuradio import analog
from gnuradio import blocks
from gnuradio import digital
from gnuradio import eng_notation
from gnuradio import filter
from gnuradio import gr
from gnuradio.eng_option import eng_option
from gnuradio.filter import firdes
from optparse import OptionParser
import math
import osmosdr
import time


class gr_omnicon_flow(gr.top_block):

    def __init__(self, freq, ppm, osmosdr_args):
        gr.top_block.__init__(self, "gr_omnicon")

        self.msgq_out = blocks_message_sink_0_msgq_out = gr.msg_queue(0)
        ##################################################
        # Variables
        ##################################################
        self.xlate_bandwidth = xlate_bandwidth = 15.0e3
        self.samp_rate = samp_rate = 1.2e6
        self.xlate_decimation = xlate_decimation = int(samp_rate/(xlate_bandwidth*3.2))
        self.baud_rate = baud_rate = 2400
        self.lowpass_decimation = lowpass_decimation = int((samp_rate/xlate_decimation)/(baud_rate*4))
        self.freq_offset = freq_offset = 250000
        self.sps = sps = (samp_rate/xlate_decimation/lowpass_decimation)/baud_rate
        self.omega_rel_limit = omega_rel_limit = ((2450.0-2400.0)/2400.0)
        self.gain_omega = gain_omega = 0
        self.gain_mu = gain_mu = 0.1
        self.freq_tune = freq_tune = freq-freq_offset

        ##################################################
        # Blocks
        ##################################################
        self.rtlsdr_source_0 = osmosdr.source(args=osmosdr_args)
        self.rtlsdr_source_0.set_sample_rate(samp_rate)
        self.rtlsdr_source_0.set_center_freq(freq_tune, 0)
        self.rtlsdr_source_0.set_freq_corr(ppm, 0)
        self.rtlsdr_source_0.set_dc_offset_mode(0, 0)
        self.rtlsdr_source_0.set_iq_balance_mode(0, 0)
        self.rtlsdr_source_0.set_gain_mode(True, 0)
        self.rtlsdr_source_0.set_gain(42, 0)
        self.rtlsdr_source_0.set_if_gain(10, 0)
        self.rtlsdr_source_0.set_bb_gain(10, 0)
        self.rtlsdr_source_0.set_antenna("", 0)
        self.rtlsdr_source_0.set_bandwidth(0, 0)
          
        self.low_pass_filter_0 = filter.fir_filter_fff(lowpass_decimation, firdes.low_pass(
        	1, samp_rate/xlate_decimation, baud_rate, (baud_rate)/10, firdes.WIN_HAMMING, 6.76))
        self.freq_xlating_fir_filter_xxx_0 = filter.freq_xlating_fir_filter_ccc(xlate_decimation, (firdes.low_pass(1, samp_rate, xlate_bandwidth, xlate_bandwidth/20 )), freq_offset, samp_rate)
        self.digital_clock_recovery_mm_xx_0 = digital.clock_recovery_mm_ff(sps, gain_omega, 0.5, gain_mu, omega_rel_limit)
        self.digital_binary_slicer_fb_0 = digital.binary_slicer_fb()
        self.dc_blocker_xx_0 = filter.dc_blocker_ff(500, True)
        self.blocks_message_sink_0 = blocks.message_sink(gr.sizeof_char*1, blocks_message_sink_0_msgq_out, False)
        self.analog_quadrature_demod_cf_0_0_0 = analog.quadrature_demod_cf(1)

        ##################################################
        # Connections
        ##################################################
        self.connect((self.analog_quadrature_demod_cf_0_0_0, 0), (self.dc_blocker_xx_0, 0))
        #self.connect((self.blocks_message_sink_0, 'msg'), (self, 0))
        self.connect((self.dc_blocker_xx_0, 0), (self.low_pass_filter_0, 0))
        self.connect((self.digital_binary_slicer_fb_0, 0), (self.blocks_message_sink_0, 0))
        self.connect((self.digital_clock_recovery_mm_xx_0, 0), (self.digital_binary_slicer_fb_0, 0))
        self.connect((self.freq_xlating_fir_filter_xxx_0, 0), (self.analog_quadrature_demod_cf_0_0_0, 0))
        self.connect((self.low_pass_filter_0, 0), (self.digital_clock_recovery_mm_xx_0, 0))
        self.connect((self.rtlsdr_source_0, 0), (self.freq_xlating_fir_filter_xxx_0, 0))


def main(top_block_cls=gr_omnicon_flow, options=None):

    tb = top_block_cls(444.000e6, 34, "")
    tb.start()
    try:
        while True:
            print [ord(i) for i in tb.msgq_out.delete_head().to_string()]
    except KeyboardInterrupt:
        pass
    tb.stop()
    tb.wait()


if __name__ == '__main__':
    main()
