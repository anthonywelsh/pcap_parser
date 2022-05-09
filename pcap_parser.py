import argparse
import sys
import os
import pyshark
import csv

# reads in pcap file as second positional arg from CLI
# only produce packet summaries from pcap
cap = pyshark.FileCapture(sys.argv[2], only_summaries=True)
noList = []
timeList = []
sourceList = []
destinationList = []
protocolList = []
lenList = []
infoList = []

# iterates over elements in cap and create str objects
# split strings into lists and append to created lists by element
for packet in cap:
    line = str(packet)
    formattedLine = line.split(" ")
    noList.append(formattedLine[0])
    timeList.append(formattedLine[1])
    sourceList.append(formattedLine[2])
    destinationList.append(formattedLine[3])
    protocolList.append(formattedLine[4])
    lenList.append(formattedLine[5])
    infoList.append(formattedLine[6])
    rows = zip(noList, timeList, sourceList, destinationList, protocolList, lenList, infoList)


# writes data to csv file
with open('TestCap3.csv', "w") as f:
    writer = csv.writer(f)
    for row in rows:
        writer.writerow(row)


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
