## gr_omnicon

gr_omnicon is an attempt to reverse engineer some parts of Kamstrup's wireless protocol for smart meters. The protocol is called OMNICON in marketing material and may be an implementation of the EN13757-5 Wireless M-Bus standard. When run from command line gr_omnicon outputs some of the fields of the over-the-air messages.

### About the protocol

The OMNICON system is a mesh network usually operating at 444MHz in Europe. The nodes in the meshnet are individual smart meters. Meters are queried by concentrators over-the-air for their usage data and use intermediary meters to relay the data if out of range of the concentrator. For more info see comments in the code.

### Usage

The main application is gr_omnicon.py. For a complete list of options run:

````
$ ./gr_omnicon.py --help
````

When used with gr-osmosdr compatible devices the defaults should suffice. 

### Dependencies

Only tested with the following versions
* Python-2.7.10
* Gnuradio-3.7.9
* Gr-osmosdr-0.1.4 with optional rtl-sdr-0.5.3
* Crcmod-1.7

### License

General Public License (GPL) v3
