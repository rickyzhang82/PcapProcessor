What
=====



How
====

First, build dependency library PcapPlusPlus from my forked repository.

```
git clone -b my-master https://github.com/rickyzhang82/PcapPlusPlus
```

In FreeBSD

```
./configure-freebsd.sh
gmake all
sudo gmake install
```

In Linux

```
./configure-linux.sh
make all
sudo make install
```

Secondly, build PcapProcessor application.

```
git clone https://github.com/rickyzhang82/PcapProcessor
./clean-build.sh
```

Thirdly, Use the following Python script to generate pcap file list which excludes any missing capturing by libpcap. The missing caputring log `capture.log` is generated by `PacketSorter`. 

Replace `pcap_root_file_path` with `PacketSorter` output directory. 

```Python
import glob
import os.path

pcap_root_file_path = '/mnt/data/keras-data/tcpsorter/tcpsorter.16JAN2020'
capture_log_file_path = os.path.join(pcap_root_file_path, 'capture.log')
pcap_lst_file_path = os.path.join(pcap_root_file_path, 'pcap.lst')


PCAP_FILE_FORMAT = '%s-%s.pcap'
MISSING_PACKET_PREFIX = 'Found missing packet:'

exclude_pcap_file_list = list()

source_pcap_file_list = glob.glob(os.path.join(pcap_root_file_path, '*.pcap'))


with open(capture_log_file_path, 'r') as cap_log_file:
    for line in cap_log_file:
        if not line.startswith(MISSING_PACKET_PREFIX):
            continue
        split_list = line.split(",")
        if len(split_list) >= 2:
            host_pairs_str = split_list[1].strip()
            if host_pairs_str.find(' => ') != -1:
                host_pairs = host_pairs_str.split(' => ')
            else:
                host_pairs = host_pairs_str.split(' <= ')

            if 2 == len(host_pairs):
                l_host = host_pairs[0].replace(':', '.').strip()
                r_host = host_pairs[1].replace(':', '.').strip()
                exclude_pcap_file_list.append(PCAP_FILE_FORMAT % (l_host, r_host))
                exclude_pcap_file_list.append(PCAP_FILE_FORMAT % (r_host, l_host))


#print(exclude_pcap_file_list)
print('# of exclude pcap file list: %d' % len(exclude_pcap_file_list))
#print(pcap_file_list)
print('# of source pcap file list: %d'% len(source_pcap_file_list))

# remove exclude pcap file list
tgt_pcap_file_list = list()

for src_file in source_pcap_file_list:
    should_exclude = False
    for exclude_file in exclude_pcap_file_list:
        if src_file.find(exclude_file) != -1:
            should_exclude = True
    if not should_exclude:
        tgt_pcap_file_list.append(src_file)

print('# of target pcap file list: %d' % len(tgt_pcap_file_list))

with open(pcap_lst_file_path, 'w') as pcap_lst_file:
    for tgt_pcap_file_path in tgt_pcap_file_list:
        pcap_lst_file.write('%s\n' % tgt_pcap_file_path)
```

Last but not the least, run `PcapProcessor` to generate modified packet files to model training. Output directory is hardcoded. Replace `OUTPUT_ROOT` in `src/main.cpp` if necessary.

```
./PcapProcessor pcap.lst
```