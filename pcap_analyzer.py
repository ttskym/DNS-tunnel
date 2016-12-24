from scapy.all import *
from functools import wraps

import numpy as np
import matplotlib.pyplot as plot

import glob
import os
import heapq
import tldextract
import re

# 包处理框架
def frame(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        pacp_path = args[0]
        t_list = []
        attr_list = []

        with PcapReader(pacp_path) as pkts:
            for pkt in pkts:
                try:
                    time, attr = func(pkt = pkt)
                    t_list.append(time)
                    attr_list.append(attr)
                except:
                    continue
        t_list = [time - int(t_list[0]) for time in t_list]
        return t_list, attr_list
    return wrapper


#提取元祖<包时间, 包长度>
@frame
def pkt_len(*args, **kwargs):
    pkt = kwargs.get("pkt")
    return pkt.time, pkt.len


#提取<包时间, 查询主机名>
@frame
def pkt_host(*args, **kwargs):
    pkt = kwargs.get('pkt')
    return pkt.time, pkt[DNSQR].qname.decode()

@frame
def pkt_nscount(*args, **kwargs):
    pkt = kwargs.get('pkt')

    return pkt.time, pkt[DNS].nscount != 0

@frame
def pkt_req_interval(*args, **kwargs):
    pkt = kwargs.get('pkt')
    if pkt.haslayer(DNS) and pkt.haslayer(DNSRR) == 0:
        return pkt.time, pkt.time





def req_interval(pcap_path):
    req_time, *_ = pkt_req_interval(pcap_path)
    req_time = iter(req_time)
    y_attr = []
    t1 = next(req_time)
    while True:
        try:
            t2 = next(req_time)
            interval = t2 - t1
            y_attr.append(interval)
            t1 = t2
        except StopIteration:
            break
    x_attr = [i+1 for i in range(len(y_attr))]
    draw(os.path.dirname(pcap_path) + '/picture/' + os.path.basename(pcap_path) + '_interval.png', 'req_interval (s)', x_attr, y_attr)
    return statistics('req_interval', y_attr)


def pcap_len(pcap_path):
    x_attr, y_attr = pkt_len(pcap_path)
    x_attr = [i+1 for i in range(len(y_attr))]
    draw(os.path.dirname(pcap_path) + '/picture/' + os.path.basename(pcap_path) + '_pcap_len.png', 'pcap_len', x_attr, y_attr)
    return statistics('pcap_len', y_attr)




def pic_io(pcap_path, timedelta):
    y_attr = []
    t_list, *_ = pkt_len(pcap_path)
    times = iter(t_list)
    max_time= int(t_list[len(t_list)-1]) + 1
    counter = 0
    tmp = next(times)
    for i in range(timedelta, max_time, timedelta):
        try:
            while tmp < i:
                counter += 1
                tmp = next(times)
        except StopIteration:
            continue
        y_attr.append(counter)
        counter = 0

    x_attr = [i for i in range(timedelta, max_time, timedelta)]
    plot.xlabel('pkt number per %s s' % (timedelta,))
    plot.plot(np.array(x_attr), np.array(y_attr), 'r.')
    plot.show()


# def host_io(pcap_path):
#     y_attr = []
#     t_list, attr_list = pkt_host(pcap_path)
#     max_time = int(t_list[len(t_list)-1]) + 1
#     pairs = iter(zip(t_list, attr_list))
#     tmp = next(pairs)
#     host_set = set()
#     for i in range(timedelta, max_time, timedelta):
#         try:
#             while tmp[0] < i:
#                 host_set.add(tmp[1])
#                 tmp = next(pairs)
#         except StopIteration:
#             continue
#         y_attr.append(len(host_set))
#         print(host_set)
#         host_set = set()
#     x_attr = [i for i in range(timedelta, max_time, timedelta)]
#     draw(os.path.dirname(pcap_path) + '/picture/' + os.path.basename(pcap_path) + '_host_io.png', 'host_number', x_attr, y_attr)
#     return statistics('host_io', y_attr)

def host_io(pcap_path):
    _, y_attr = pkt_host(pcap_path)
    host_set = set(y_attr)

    return len(host_set)/len(y_attr), 0

def nscount(pcap_path):
    _, y_attr = pkt_nscount(pcap_path)
    return sum(y_attr), 0

def draw(fig_name, ylabel, x_attr, y_attr):
    plot.ylabel(ylabel)
    plot.plot(x_attr, y_attr, 'r.')
    plot.savefig(fig_name)
    plot.clf()

def statistics(func_name, attr):
    average = np.average(attr)
    variance = np.var(attr)
    std = np.std(attr)
    print(func_name+':' + str(len(attr)))
    print("average: %s" % average)
    print("variance: %s" % variance)
    print("cv: %s", std/average)
    print()
    return std/average, variance


def draw_bar(x, y, x_attr, sizes, name):
    colors = ['red', 'green', 'blue']
    plot.figure(figsize=(14,5))
    for i in range(len(x)):
        plot.bar(x[i], y[i], width=4, label = sizes[i],facecolor=colors[i])
        plot.xticks(x[i], x_attr, rotation=0)

    plot.legend()
    plot.savefig('/Users/liujingkun/Exp/dns_tunneling/data/catch_data/exp/picture/'  + name + '.png')
    plot.clf()

def main(args):
    y_ave = []
    y_var = []
    flag = 0

    sizes = []
    x_attr = []

    for path in args:
        sizes.append(path.split(r'/')[-2])
        files = glob.glob(path)
        y_ave.append(list())
        y_var.append(list())
        for file in files:
            if file.endswith(r'.pcap'):
                print('\r\n' + '_' * 30)
                print(file)
                print('-' * 30 + '\r\n')
                if flag == 0:
                    x_attr.append('\n'.join(os.path.basename(file).split(r'_')[0:2]))

                ave, var = pcap_len(file)
                y_ave[-1].append(ave)
                y_var[-1].append(var)
        flag = 1

    x = []
    x_num = len(y_ave[0])
    for i in range(len(args)):
        x.append(list())
        for j in range(x_num):
            x[-1].append(3 * i + 20 * j)

    # name = req_interval.__name__
    # draw_bar(x, y_ave, x_attr, sizes, name + '_cv')
    # draw_bar(x, y_var, x_attr, sizes, name + '_var')


if __name__ == '__main__':

    paths = [
              '/Users/liujingkun/Exp/dns_tunneling/data/catch_data/exp/1000/*',
             ]


    main(paths)


    # for path in paths:
    #     for file in glob.glob(path):
    #             if file.endswith(r'.pcap'):
    #                 print(file)
    #                 print(pcap_len(file))file
    # main(char_frequency, paths, gram_n=1)
