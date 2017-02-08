import os
import json
import time

from concurrent.futures import ProcessPoolExecutor

cmd_list = []


def cmd_generator():
    dir = '/home/ljk/data/dataset/'
    with open('data_filtered.txt') as f:
        data = json.load(f)

    for domain in data:
        for ip in data[domain]:
            ip_src, ip_dst = ip.split()
            # no -2
            cmd = 'tshark -r /home/ljk/data/5mindata/5min_00000_20130523142355 -n -R "ip.addr == ' + ip_src + \
                      ' and ip.addr == ' + ip_dst + ' and dns.qry.name contains "' + domain + '""' \
                      + ' -w ' + dir + domain + '_' + ip_src + '_' + ip_dst +'.pcap'
            cmd_list.append(cmd)


def system_exec(cmd_str):
    os.system(cmd_str)

if __name__ == '__main__':
    cmd_generator()
    tmp = []

    with ProcessPoolExecutor() as pool:
        for cmd in cmd_list:
            tmp.append(pool.submit(system_exec, cmd))

    for a in tmp:
        a.result()
    # print cmd_list
    # cmd_generator()
    # print(cmd_list)