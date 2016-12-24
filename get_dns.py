from scapy.all import *
from functools import wraps
from concurrent.futures import ProcessPoolExecutor
from concurrent.futures import ThreadPoolExecutor

import glob
import tldextract

register_domains = set()

def parser(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        dict = {}
        name_all = []
        file_name = args[0]
        with PcapReader(file_name) as file:
            for pkt in file:
                if pkt.haslayer(DNSRR):
                    try:
                        name, result = func(pkt=pkt)
                        if result not in dict:
                            dict[result] = 1
                        else:
                            dict[result] += 1
                        name_all.append(name)
                    except:
                        continue
        return name_all, dict
    return wrapper

@parser
def getTopDomain(*args, **kwargs):
    qname =  kwargs.get('pkt')[DNSQR].qname.decode()
    if qname[-1] == r'.':
        qname = qname[:-2]
    tldhelper = tldextract.extract(qname)
    return qname, tldhelper.registered_domain

@parser
def getIPbyDomain(*args, **kwargs):
    # domain = kwargs.get('domain')
    pkt = kwargs.get('pkt')
    if pkt[DNSQR].qname.decode().find(domain) != -1:
        return pkt[IP].src + ' ' + pkt[IP].dst
        #return pkt[IP].dst

@parser
def getIPbyName(*args, **kwargs):
    pkt = kwargs.get('pkt')
    if pkt[DNSQR].qname.decode() == 'www.baidu.com.':
        return pkt[IP].src + ' ' + pkt[IP].dst
        #return pkt[IP].dst

def main(domain):
    result_list = []
    pool_list = []
    all_result = {}
    name_all = []

    path = '/Users/liujingkun/Exp/dns_tunneling/data/exp_data/small_file/little/*'
    file = glob.glob(path)

    # 多进程执行
    with ProcessPoolExecutor() as pool:
        for s in file:
            pool_list.append(pool.submit(getIPbyDomain, s))

    # with ThreadPoolExecutor() as pool:
    #     for s in file:
    #         pool_list.append(pool.submit(getIPbyDomain, s))

    # 合并各进程数据
    print(len(pool_list))
    for r in pool_list:
        result_list.append(r.result()[1])
        # name_all += r.result()[0]


    # 合并字典统计量
    for entry in result_list:
        for key in entry.keys() & all_result.keys():
            all_result[key] += entry[key]
            del entry[key]
        all_result.update(entry)

    # 从大到小排序
    result = sorted(all_result.items(), key=lambda d: d[1], reverse=True)

    with open(domain+".txt", "wt") as f:
        for name in result:
            try:
                #print(name[0].split()[1])
                f.write(''+name[0]+' '+str(name[1])+'\r\n')
            except:
                continue

    # print(name_all)
    # with open('all_dns.txt', 'wt') as f:
    #     for name in name_all:
    #         try:
    #             f.write(name+'\r\n')
    #         except:
    #             continue


def domain_helper():
    with open('../test_data/top_domain.txt', 'rt') as f:
        domains = [domain.strip() for domain in f.readlines()]

    global register_domains
    tmplist = []
    for domain in domains:
        print(domain)
        tld = tldextract.extract(domain).registered_domain
        tmplist.append(tld)

    register_domains = set(tmplist)

if __name__ == '__main__':

    domain_helper()
