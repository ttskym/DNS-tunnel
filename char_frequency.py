from scapy.all import *
from concurrent.futures import ProcessPoolExecutor

import re
import glob
import os
import tldextract

import matplotlib.pyplot as plot


def get_name():
    """针对每个pcap目录生成对应pcap的qname数据集"""

    tunnel_path = ['/Users/liujingkun/Exp/dns_tunneling/data/catch_data/exp/1000/*']
    for path in tunnel_path:
        size = path.split(r'/')[-2]
        files = glob.glob(path)
        for file in files:
            if file.endswith(".pcap") == False:
                continue
            names  = []
            file_name = '_'.join(os.path.basename(file).split(r'_')[0:2])
            with PcapReader(file) as pkts:
                for pkt in pkts:
                    try:
                        qname = pkt[DNSQR].qname.decode()
                        if qname[-1] == r'.':
                            qname = qname[:-1]
                        names.append(qname)
                    except:
                        continue
            with open('/Users/liujingkun/Exp/dns_tunneling/data/catch_data/exp/name/'+size+'/'+file_name, 'wt') as f:
                for name in names:
                    f.write(name + '\r\n')



def compute(data, gram_n, flag):
    gram_dict = {}
    len_sum = 0
    for host_name in data:
        # print(tldextract.extract(host_name))
        subdomain = tldextract.extract(host_name)
        if flag == 1:
            subdomain = tldextract.extract(host_name)[0]

        else:
            subdomain = host_name
        # subdomain = test.sub('', subdomain)
        # subdomain = abc.sub('', subdomain)
        # subdomain = pattern.sub('', subdomain)

        len_sum += len(subdomain)
        # print(subdomain)

        for i in range(len(subdomain) - 1 - gram_n):
            if subdomain[i:i + gram_n] in gram_dict:
                gram_dict[subdomain[i:i + gram_n]] += 1
            else:
                gram_dict[subdomain[i:i + gram_n]] = 1

    return len_sum, gram_dict


def char_frequency(sample_file, gram_n):
    dic_all = []
    pool_list = []
    pattern = re.compile(r'[^a-z]')
    test = re.compile((r'.test'))
    abc = re.compile(r'.abc')
    gram_dict = {}
    len_sum = 0
    with open(sample_file, "rt", encoding='utf-8') as file:
        host_names = file.readlines()

    if sample_file.find('result') == -1:
        flag = 1
    else:
        flag = 0

    with ProcessPoolExecutor() as pool:
        if len(host_names) > 100000:
            for i in range(100000, len(host_names), 100000):
                pool_list.append(pool.submit(compute, host_names[i-100000:i], gram_n, flag))
        else:
            pool_list.append(pool.submit(compute, host_names, gram_n, flag))

    for process in pool_list:
        len_sum += process.result()[0]
        dic_all.append(process.result()[1])

    for dic in dic_all:
        for key in dic.keys() & gram_dict.keys():
            gram_dict[key] += dic[key]
            del dic[key]
        gram_dict.update(dic)


    for key in gram_dict.keys():
        gram_dict[key] = gram_dict.get(key) / len_sum

    print(gram_dict)
    return gram_dict


def draw(path_name, x_attr, y_attr):
    colors = ['r', 'g', 'y', 'b', 'c', 'm', 'k', 'w', '#FF83FA']
    x = list(range(len(x_attr)))
    for size_item in y_attr.items():
        flag = 0
        size_key = size_item[0]
        plot.figure(figsize=(100, 20))
        for file_item in size_item[1].items():
            file_key = file_item[0]
            plot.plot(x, file_item[1], label = file_key, color=colors[flag])
            plot.xticks(x, x_attr, rotation=90)
            flag += 1
        # plot.ylim(0.0, 0.13)
        plot.legend()
        plot.savefig(path_name + str(size_key) +'_pure'  + '.png')
        plot.clf()


def main(args):
    xx = []
    x = []
    for i in range(97, 122):
        x.append(chr(i))
    for i in range(65, 90):
        x.append(chr(i))
    for i in range(48, 57):
        x.append(chr(i))
    x.append('_')

    for i in x:
        for j in x:
            xx.append(i+j)
    xx = xx[600:1200]
    print(len(xx))
    y = {}

    for path in args:
        # sizes.append(path.split(r'-')[-1].split(r'.')[0])
        # size -> 路径名 作为第一层字典key
        size = path.split(r'/')[-2]
        files = glob.glob(path)
        y[size] = {}
        for file in files:
            # 打印文件名
            print('\r\n' + '_' * 30)
            print(file)
            print('-' * 30 + '\r\n')
            # file_name -> 包文件名 作为第二层字典key
            # file_name = ('\n'.join(os.path.basename(file.split(r'_')[0:2]))
            file_name = os.path.basename(file)

            data = char_frequency(file, 2)

            y[size][file_name] = list()
            for key in xx:
                if data.get(key):
                    y[size][file_name].append(data.get(key))
                else:
                    y[size][file_name].append(0)

    draw('/Users/liujingkun/Exp/dns_tunneling/data/catch_data/exp/picture/', xx, y)


if __name__ == '__main__':
    paths = ['/Users/liujingkun/Exp/dns_tunneling/data/catch_data/exp/name/1000/*',
             ]
    # get_name()
    main(paths)



