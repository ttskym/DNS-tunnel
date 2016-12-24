from scapy.all import *
from concurrent.futures import ProcessPoolExecutor

import matplotlib.pyplot as plot

import json
import glob

def get_type(file):

    data = {}
    with PcapReader(file) as pkts:
        for pkt in pkts:
            if pkt.haslayer('DNS'):
                if pkt.haslayer('DNSRR') == False:
                    try:
                        qtype = pkt[DNSQR].qtype
                    except:
                        continue
                    key = str(qtype)
                    if key not in data:
                        data[key] = 1
                    else:
                        data[key] += 1

    return data


def type_json(filename):
    sum = 0
    other = 0
    dns_type = {'1': 'A',
                '5': 'CNAME',
                '15': 'MX',
                '16': 'TXT',
                '10': 'NULL',
                '28': 'AAAA',
                '2': 'NS',
                '12': 'PTR',
                '3': 'MD',
                '33':'SRV',
                '6': 'SOA',
                '255': '*',
                '0': 'SIG'
                }
    with open(filename,'rt') as file:
        data = json.load(file)

    data = sorted(data.items(), key=lambda a: a[1], reverse=True)
    print(data)
    for item in data:
        sum += item[1]
    for item in data:
        radio = round(int(item[1]) / sum * 100, 2)
        if item[0] in dns_type:
            print(dns_type.get(item[0]) + ':', end='')
            print(str(radio) + '%')
        else:
            if radio > 0.00001:
                print(item[0] + ':', end='')
                print(str(radio) + '%')

            else:
                other += radio

    print('other:' + str(other) + '%')


if __name__ == '__main__':
    # 获取1小时DNS流量的查询类型统计数据
    # path = ''
    # pool_list = []
    # result_list = []
    # all_result = {}
    #
    # files = glob.glob(path)
    # with ProcessPoolExecutor() as pool:
    #     for file in files:
    #         print(file)
    #         if file.endswith(r'.pcap'):
    #             pool_list.append(pool.submit(get_type, file))
    #
    # for pro in pool_list:
    #     result_list.append(pro.result())
    #
    # for entry in result_list:
    #     for key in entry.keys() & all_result.keys():
    #         all_result[key] += entry[key]
    #         del entry[key]
    #     all_result.update(entry)
    #
    # print(all_result)
    # with open('', 'wt') as file:
    #     json.dump(all_result, file)

    type_json('/Users/liujingkun/Exp/dns_tunneling/data/analyze_data/other/type.txt')
