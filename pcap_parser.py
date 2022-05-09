import argparse
import sys
import os
import pyshark

# reads in pcap file as second positional arg from CLI
# only produce packet summaries from pcap
cap = pyshark.FileCapture(sys.argv[2], only_summaries=True)


# argument parser for receiving CLI args
def process_pcap(file_name):
    print('Opening {}...'.format(file_name))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='PCAP reader')
    parser.add_argument('--pcap', metavar='<pcap file name>',
                        help='pcap file to parse', required=True)
    args = parser.parse_args()

    file_name = args.pcap
    if not os.path.isfile(file_name):
        print('"{}" does not exist'.format(file_name), file=sys.stderr)
        sys.exit(-1)

    process_pcap(file_name)
    sys.exit(0)
