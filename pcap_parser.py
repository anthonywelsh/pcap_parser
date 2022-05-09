import argparse
import sys
import os
import csv
import pandas as pd
import pyshark
import seaborn as sns
import matplotlib.pyplot as plt


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


# iterates over elements in pcap and create str objects
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


# read-in created csv file with pcap data
# add columns to dataframe for manipulating data with pandas
# get dataframe values for packet length and count values in series
df = pd.read_csv('TestCap3.csv')
df.columns = ['No.', 'Time', 'Source', 'Destination', 'Protocol', 'Length', 'Info']
length_counts = df['Length'].value_counts


# plot matplotlib histogram with seaborn interface
sns.set()
fig, ax = plt.subplots(figsize=(10, 6))
plt.hist(df['Length'], alpha=0.5, color=['g'], bins=15)
plt.xlim([0, 1600])
plt.ylim([0, 6000])
# plt.yticks(np.arange(1, 100, 5000))
# plt.xticks(np.arange(1, 100, 1500))
plt.xlabel('Byte Values')
plt.ylabel('Frequency')


# print mean and variance of df to terminal and show histogram plot
print("Mean is:", df['Length'].mean())
print("Variance is:", df['Length'].var())
plt.savefig('TestCap3.png', format='png')
plt.show()


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
