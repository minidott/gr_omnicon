#!/usr/bin/env python2
# -*- coding: utf-8 -*-

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from __future__ import print_function
import argparse
from datetime import datetime
from collections import deque

import gnuradio.eng_notation
import crcmod

import gr_omnicon_flow


class Message(object):
    """
    Contains all the data in a single transmission

    Keyword arguments:
    filehandle -- a file handle for reading the remaining bits after the syncword has been found.
    """
    def __init__(self, filehandle):
        self._message = []
        length_bits = filehandle.read(16)  # todo check read error exception
        if len(length_bits) != 16:
            quit()
        message_length = self._manchester2byte(length_bits)
        self._message.append(message_length)
        for _ in range(message_length - 1):
            byte = self._manchester2byte(filehandle.read(16))
            self._message.append(byte)

        crc = crcmod.predefined.Crc("crc-16-mcrf4xx")
        # crcmod only accepts strings so convert the list of ints to plain string without markings
        crc.update("".join([chr(i) for i in self._message]))
        if crc.hexdigest() == "0000":
            self._crc_ok = True
        else:
            self._crc_ok = False

    @staticmethod
    def _manchester2byte(bits):
        """
        Takes 16 manchester encoded bits in gnuradio unpacked form and returns a byte
        """
        assert len(bits) == 16
        # throw away the redundant manchester encoding bits
        bit_list = [ord(bit) for i, bit in enumerate(bits) if i % 2]
        byte = 0
        for bit in bit_list:
            byte <<= 1
            byte |= bit
        return byte

    class Type(object):
        query = 1
        reply = 2
        query_type2 = 3
        reply_type2 = 4
        announce = 5
        announce_type2 = 6
        unknown = 7

    def get_type(self):
        """
        The meshnet is mainly query/response driven. Concentrators send querys to meters and they reply to the same
        concentrator using the same route as the query. The message type is stored in the 3rd byte of the message.

        There are other message types besides the regular query and reply but their meaning is unknown.
        Query and reply type 2 looks the same as the regular query and replys but are rarely used.
        The announce type messages got no embedded addresses. Perhaps they are used as bootstrap announce ping for
        new meters. Very rare.
        """
        try:
            if self._message[1] == 0xE8:
                return_type = self.Type.query
            elif self._message[1] == 0xA8:
                return_type = self.Type.reply
            elif self._message[1] == 0xF8:
                return_type = self.Type.query_type2
            elif self._message[1] == 0xB8:
                return_type = self.Type.reply_type2
            elif self._message[1] == 0xC0:
                return_type = self.Type.announce
            elif self._message[1] == 0xD0:
                return_type = self.Type.announce_type2
            else:
                return_type = self.Type.unknown
        except IndexError:
            print("Message with unknown format. Please file a bugreport.")
            return_type = self.Type.unknown
        return return_type

    def graphviz_relations(self, color_sending=True, color="pink"):
        """
        Return a string showing the relationship between the addresses in the message in graphviz (www.graphviz.org)
        format. Example "0abcdef0" -> "0abcdef1" -> "0abcdef2"

        :param color_sending: If set, color the address of the currently transmitting node
        :param color: The color to use (www.graphviz.org/doc/info/colors.html)
        """
        address, _, is_sending = self.get_addresses()
        return_list = []
        hexformated_list = ["".join([format(j, "02X") for j in a]) for a in address]
        for i, hexformat in enumerate(hexformated_list):
            return_list.append("\"")
            return_list.append(hexformat)
            return_list.append("\"")
            if i != len(hexformated_list) - 1:
                return_list.append(" -> ")
        return_list.append("\n")
        if color_sending:
            for i, sending in enumerate(is_sending):
                if sending:
                    return_list.append("\"")
                    return_list.append(hexformated_list[i])
                    return_list.append("\"  [color=")
                    return_list.append(color)
                    return_list.append(", style=filled];\n")
        return "".join(return_list)

    def valid_crc(self):
        return self._crc_ok

    def str_message_hex(self):
        return "Message: %s\n" % " ".join([format(i, "02X") for i in self._message])

    def str_type(self):
        message_type = self.get_type()
        if message_type is self.Type.query:
            return "Message type: query\n"
        elif message_type is self.Type.reply:
            return "Message type: reply\n"
        elif message_type is self.Type.query_type2:
            return "Message type: query type 2?\n"
        elif message_type is self.Type.reply_type2:
            return "Message type: reply type 2?\n"
        elif message_type is self.Type.announce:
            return "Message type: bootstrap announce ping?\n"
        elif message_type is self.Type.announce_type2:
            return "Message type: bootstrap announce ping type 2?\n"
        else:
            return "Message type: unknown\n"

    def get_addresses(self):
        """
        Return a tuple with info about the addresses contained in the message.

         Each message can contain up to at least 8 addresses with hardcoded info about how the message should be
         routed. The low nibble of the message's 3rd byte is the total number of addresses in the message and the high
         nibble is how many hops was left at time of transmission.

         Each address is 28-bit number with a 4-bit flag attached to it. The least significant bit of the flag indicates
         that the address belongs to a concentrator. The meaning of the other 3 bits are unknown. A meter's 28-bit
         number appears to be the same as the serial number written on it's front label.
        """
        addresses = []
        flags = []
        is_sending = []
        try:
            num_addresses = self._message[2] & 0x0F
            current_hop = (self._message[2] & 0xF0) >> 4
            unordered_address = ([self._message[3+i*4:7+i*4] for i in range(num_addresses)])
            for i in range(num_addresses):
                current_address = unordered_address[(current_hop + i) % num_addresses]
                flag = (current_address[0] & 0xF0) >> 4
                current_address[0] &= 0x0F
                flags.append(flag)
                addresses.append(current_address)
                if i == (num_addresses - current_hop - 1):
                    is_sending.append(True)
                else:
                    is_sending.append(False)
        except IndexError:
            print("Message with unknown format. Please file a bugreport.")
        return addresses, flags, is_sending

    def str_addresses(self):
        addresses, flags, is_sending = self.get_addresses()
        return_string = []
        try:
            for i, address in enumerate(addresses):
                return_string.append("Address %s: " % str(i+1))
                return_string.append(" ".join([format(j, "02X") for j in address]))
                return_string.append(", Flags: %s" % hex(flags[i]))
                if is_sending[i]:
                    return_string.append(" <- sending")
                return_string.append("\n")
        except IndexError:
            print("Message with unknown format. Please file a bugreport.")
        return "".join(return_string)

    def get_data(self):
        """
        Returns the data payload of the message.

        Each message carry a data payload which is always a multiple of 16-bytes. 16-byte (128-bit) is a common block
        length in block ciphers and since the data is high entropy without any obvious patterns it's probably encrypted.

        Different concentrators often send the same payload to several different meters. This suggests that the data
        is encrypted with a symmetric key shared by all meters. Each data block can often be seen several times
        in the same message suggesting the use of ECB as block mode.
        """
        data_blocks = []
        try:
            num_addresses = self._message[2] & 0x0F
            data = self._message[3 + num_addresses*4:-2]
            if len(data) % 16 != 0:
                print("Holy shit, data not 16 byte multiple")
            for i in range(len(data) / 16):
                data_blocks.append(data[i*16:i*16+16])
        except IndexError:
            print("Message with unknown format. Please file a bugreport.")
        return data_blocks

    def str_data(self):
        data_blocks = self.get_data()
        return_string = []
        for i, data in enumerate(data_blocks):
            return_string.append("Data block %s: " % str(i+1))
            return_string.append(" ".join([format(j, "02X") for j in data]))
            return_string.append("\n")
        return "".join(return_string)

    def __str__(self):
        return "".join((self.str_message_hex(), self.str_type(), self.str_addresses(), self.str_data()))


class FlowWrapper(object):
    """
    Gnuradio msg_queue returns an arbitrary amount of data. This class wraps a msg_queue to mimic a filehandle and
    optionally write all data from the msg_queue to a file.
    """
    def __init__(self, msg_queue, outfile=None):
        self._msg_queue = msg_queue
        self._bit_queue = deque()
        self._outfile = outfile

    def read(self, num):
        while len(self._bit_queue) < num:
            self._bit_queue.extend([i for i in self._msg_queue.delete_head().to_string()])
        return_string = "".join([self._bit_queue.popleft() for _ in range(num)])
        if self._outfile is not None:
            self._outfile.write(return_string)
        return return_string

    def close(self):
        pass


def open_file(name, mode):
    filehandle = None
    if name is not None:
        try:
            filehandle = open(name, mode)
        except IOError as exception:
            print(exception)
            quit()
    return filehandle


def main():
    parser = argparse.ArgumentParser(description="gr_omnicon decode some of the metadata in Kamstrup's OMNICON "
                                                 "meshnet for smartmeters. If no argument is given data will be "
                                                 "read from the first gr-osmosdr compatible device.")
    parser.add_argument('-o', '--debug_output', help="write raw bits to file for debug")
    parser.add_argument('-i', '--debug_input', help="replay data previously written to file with the -o option")
    parser.add_argument('-g', '--graphfile', help="write a text file with info about the meshnet's node relations. "
                        "This file can be made into an image using the dot tool from http://www.graphviz.org/")
    parser.add_argument('-f', '--freq', default="444.0e6", help="frequency to listen on. Accept engineering notation "
                        "with default \"444M\". The following frequencies are also mentioned in marketing materials: "
                        "434.05, 439.41, 440.05625 444.05, 444.075, 444.15, 444.3, 444.4, 444.45, 444.55, 444.675, "
                        "444.7, 444.725, 448.725MHz")
    parser.add_argument('-p', '--ppm', default=0, type=int, help="frequency correction value in ppm")
    parser.add_argument('-x', '--osmosdr_args', default="numchan=1", help="optional arguments to osmosdr. e.g. "
                        "\"rtl_tcp=10.0.0.2:1234\" for connecting to an rtl_tcp server")
    args = parser.parse_args()

    if args.debug_output and args.debug_input:
        print("Writing debug file while reading from debugfile makes no sense")
        quit()

    infile = open_file(args.debug_input, "rb")
    outfile = open_file(args.debug_output, "wb")
    graphfile = open_file(args.graphfile, "w")

    if infile is None:
        freq = gnuradio.eng_notation.str_to_num(args.freq)
        flow = gr_omnicon_flow.gr_omnicon_flow(freq, args.ppm, args.osmosdr_args)
        infile = FlowWrapper(flow.msgq_out, outfile)
        flow.start()
        print("\nIf no messages are printed within a few hours try a different frequency,")
        print("check the antenna or make sure the supplied ppm correction is correct.")
        print("Listening on frequency " + gnuradio.eng_notation.num_to_str(freq) + " with osmosdr "
              "arguments \"" + args.osmosdr_args + "\"")
        print("="*80)

    if graphfile is not None:
        graphfile.write("strict digraph meshnet {")

    syncword = 0
    while True:
        try:
            bit = infile.read(1)  # todo check read error exception
            if bit is None or bit == "":
                break
            # Each transmission begins with a lead-in with 100 bits of alternating 0 & 1s.
            # After the lead-in there is a syncword = 00001111 and then the actual data.
            # bits are in gnuradio unpacked form.
            syncword <<= 1
            syncword |= ord(bit) & 0x01
            syncword &= 0xFFFFFFFF  # cap the syncword to 32 bits
            if syncword == 0x5555550F:
                message = Message(infile)
                if message.valid_crc():
                    if args.debug_input is None:
                        print("Message received: " + str(datetime.now()))
                    print(str(message))
                    if graphfile is not None:
                        graphfile.write(message.graphviz_relations())
                else:
                    print("Message with bad CRC", end="\n\n")
        except KeyboardInterrupt:
            break

    if graphfile is not None:
        graphfile.write("}")
        graphfile.close()
    if outfile is not None:
        outfile.close()
    infile.close()

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        quit()
