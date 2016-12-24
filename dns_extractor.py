import tldextract
import json

from scapy.all import *
from concurrent.futures import ProcessPoolExecutor
from pprint import pprint

import glob

register_domains = set()


def parser(file_name):
    data = {}
    with PcapReader(file_name) as file:
        for pkt in file:
            if pkt.haslayer(DNSRR):
                try:
                    qname = pkt[DNSQR].qname.decode()
                    ip = pkt[IP].dst + ' ' + pkt[IP].src
                    tld = tldextract.extract(qname).registered_domain
                    if tld in register_domains:
                        data.setdefault(tld, dict()).setdefault(ip, 0)
                        data[tld][ip] += 1
                except KeyboardInterrupt:
                    pprint(data)
                    raise KeyboardInterrupt
                except:
                    continue

    return data


def main():
    pool_list = []
    result_list = []
    data = {}

    path = '/home/ljk/data/split/*'
    file = glob.glob(path)

    # 多进程执行
    with ProcessPoolExecutor() as pool:
        for s in file:
            pool_list.append(pool.submit(parser, s))

    # 合并各进程数据
    print(len(pool_list))
    for r in pool_list:
        result_list.append(r.result())

    # 合并字典统计量
    for entry in result_list:
        for domain in entry.keys() & data.keys():
            for ip in entry[domain].keys() & data[domain].keys():
                data[domain][ip] += entry[domain][ip]
                del entry[domain][ip]
            data[domain].update(entry[domain])
            del entry[domain]
        data.update(entry)

    with open("extractor_data.txt", "wt") as f:
        json.dump(data, f)


def domain_helper():
    with open('/home/ljk/top_domain.txt', 'rt') as f:
        domains = [domain.strip() for domain in f.readlines()]

    global register_domains
    tmplist = []
    for domain in domains:
        tld = tldextract.extract(domain).registered_domain
        tmplist.append(tld)

    register_domains = set(tmplist)


if __name__ == '__main__':
    domain_helper()
    main()