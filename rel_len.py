from scapy.all import *

import matplotlib.pyplot as plot

import glob

def get_data(pcap_file):
    req_dict = {}
    len_list = []

    with PcapReader(pcap_file) as pkts:
        for pkt in pkts:
            if pkt.haslayer(DNS) and pkt.haslayer(DNSRR) == 0:
                req_dict[str(pkt[DNS].id)+ str(pkt[UDP].sport) + str(pkt[IP].src) + str(pkt[IP].dst)] = pkt.len
            else:
                try:
                    len_list.append((req_dict.pop(str(pkt[DNS].id)+ str(pkt[UDP].dport) + str(pkt[IP].dst) + str(pkt[IP].src)), pkt.len))
                except:
                    continue

    # print(len_list)
    return len_list


def draw(data, file):
    req = []
    res = []
    x = [i for i in range(len(data))]
    for item in data:
        req.append(item[0])
        res.append(item[1])

    plot.plot(x, req, label='request', color='r')
    plot.plot(x, res, label='response', color='b')

    plot.legend()
    # plot.savefig(os.path.dirname(file) + '/picture/'  + os.path.basename(file) + '_relation_len.png')
    plot.savefig('/Users/liujingkun/Exp/dns_tunneling/data/catch_data/exp/picture/normal_relation_len.png')

    plot.clf()

def main(args):
    for path in args:
        for file in glob.glob(path):
            if file.endswith(r'.pcap'):
                filename = os.path.basename(file).split(r'_')[0:2]
                draw(get_data(file), file)


if __name__ == '__main__':
    paths = ['/Users/liujingkun/Exp/dns_tunneling/data/catch_data/exp/50/*',
             '/Users/liujingkun/Exp/dns_tunneling/data/catch_data/exp/100/*',
             '/Users/liujingkun/Exp/dns_tunneling/data/catch_data/exp/1000/*',
             ]
    # main(paths)

    # 获取1小时流量的所有数据,并以,分割,存入文本
    # data = get_data('')
    # with open('./test_data/a.txt', 'wt') as f:
    #     for line in data:
    #         a, b = line
    #         f.write(str(a) +','+ str(b) + '\r\n')


    # 读取1小时的文本数据,将请求长度和响应长度解析为元组的形式,画图
    len_list = []
    with open('/Users/liujingkun/Exp/dns_tunneling/data/analyze_data/other/rel.txt', 'rt') as f:
        lines = f.readlines()
        for line in lines:
            len_list.append(tuple(line.strip().split(',')))

    draw(len_list[:50], 'normal')


