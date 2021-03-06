import matplotlib as mpl
mpl.use('Agg')
import matplotlib.pyplot as plot

from scapy.all import *

import glob
import heapq

import numpy as np

def req_res_interval(pcap_path):
    counter = 0
    y_attr = []
    dict_req = {}
    with PcapReader(pcap_path) as pkts:
        # init_time = pkts[0].time
        for pkt in pkts:
            # print(pkt.time)
            if pkt.haslayer(DNS):
                if pkt.haslayer(DNSRR):
                    try:
                        # y_attr.append(pkt.time  - dict_req.pop(str(pkt[DNS].id )) )

                        y_attr.append(pkt.time  - dict_req.pop(str(pkt[DNS].id )+ ' ' + str(pkt[UDP].dport)) )
                    except:
                        counter += 1
                        continue
                else:
                    # dict_req[str(pkt[DNS].id) ] = pkt.time
                    dict_req[str(pkt[DNS].id) + ' ' + str(pkt[UDP].sport)] = pkt.time
    top_n = int(len(y_attr) / 10)
    for i in heapq.nlargest(int(top_n / 2), y_attr):
        y_attr.remove(i)
    for i in heapq.nsmallest(int(top_n / 2), y_attr):
        y_attr.remove(i)

    x_attr = [i+1 for i in range(len(y_attr))]
    return compute('res_req_interval', y_attr)

def compute(func_name, attr):
    average = np.average(attr)
    variance = np.var(attr)
    print(func_name+':' + str(len(attr)))
    print("average: %s" % average)
    print("variance: %s" % variance)
    print()
    return average, variance

#
def draw_bar(x, y, x_attr, sizes, name):

    width = 0.25
    print(x)
    colors = ['red', 'green', 'blue']
    plot.figure(figsize=(14,5))
    for i in range(len(x)):
        plot.bar(x[i], y[i], width=width, label = sizes[i],facecolor=colors[i], align='center')
    x_a = [width+a for a in x[0]]
    print(x_a)
    plot.xticks(x_a, x_attr, rotation=0)

    plot.legend()
    # plot.savefig('/Users/liujingkun/Exp/dns_tunneling/data/catch_data/exp/picture/'  + name + '_pure.png')
    plot.savefig('/home/ljk/pic/'  + name + '_pure.png')
    plot.clf()

# def draw_bar(path_name, x, y):
#
#     plot1 = plot
#     plot2 = plot
#
#     colors = ['red', 'green', 'blue']
#     plot1.figure(figsize=(14, 5))
#     # plot2.figure(figsize=(14, 5))
#
#     flag = 0
#
#     for size_item in y.items():
#         size_key = size_item[0]
#
#         x_attr = []
#         y_ave = []
#         y_var = []
#         for file_item in size_item[1].items():
#             x_attr.append('\n'.join(file_item[0].split('_')[:2]))
#             y_ave.append(file_item[1][0])
#             y_var.append(file_item[1][1])
#
#         print(y_ave)
#         print(y_var)
#         plot1.bar(x[flag], y_ave, label=size_key, facecolor=colors[flag], width=3)
#         plot1.xticks(x[flag], x_attr, rotation=0)
#
#         y_ave.clear()
#         y_var.clear()
#
#         flag += 1
#
#     plot1.legend()
#     plot1.savefig(path_name  + 'req_res_interval_pure' + '.png')
#     plot.clf()


def main(args):
    y_ave = []
    y_var = []
    flag = 0

    sizes = []
    x_attr = []

    for path in args:
        sizes.append(path.split(r'/')[-2])
        files = glob.glob(path)
        files = sorted(files)
        y_ave.append(list())
        y_var.append(list())
        for file in files:
            if file.endswith(r'.pcap'):
                print('\r\n' + '_' * 30)
                print(file)
                print('-' * 30 + '\r\n')
                if flag == 0:
                    x_attr.append('\n'.join(os.path.basename(file).split(r'.')[0:1]))

                ave, var = req_res_interval(file)
                y_ave[-1].append(ave)
                y_var[-1].append(var)
        flag = 1

    x = []
    x_num = len(y_ave[0])
    for i in range(len(args)):
        x.append(list())
        for j in range(x_num):
            x[-1].append(0.25*i + j)
    draw_bar(x, y_ave, x_attr, sizes, req_res_interval.__name__ + '_ave')
    draw_bar(x, y_var, x_attr, sizes, req_res_interval.__name__ + '_var')



    # x = []
    # y = {}
    # for path in args:
    #     # size -> 路径名 作为第一层字典key
    #     size = path.split(r'/')[-2]
    #     y[size] = {}
    #     files = glob.glob(path)
    #     files = sorted(files)
    #     for file in files:
    #         if file.endswith('.pcap') == False:
    #             continue
    #         ##打印文件名
    #         print('\r\n' + '_' * 30)
    #         print(file)
    #         print('-' * 30 + '\r\n')
    #         # file_name -> 包文件名 作为第二层字典key
    #         file_name = os.path.basename(file)
    #         data = req_res_interval(file)
    #
    #         y[size][file_name] = data
    #
    # x_num = len(y['50'])
    # for i in range(len(y)):
    #     x.append(list())
    #     for j in range(x_num):
    #         x[-1].append(3 * i + 20 * j)

    # draw_bar('/home/ljk/pic/', x, y)



if __name__ == '__main__':
    paths = ['/home/ljk/exp/50/*',
             '/home/ljk/exp/100/*',
             '/home/ljk/exp/1000/*'
    ]
    main(paths)
