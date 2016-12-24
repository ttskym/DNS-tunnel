import json
import copy

from collections import OrderedDict
from pprint import pprint

black_list = ['10.in-addr.arp', '192.in-addr.arpa', '111.in-addr.arpa', '10.in-addr.arpa']

def domain_handler():
    with open('../test_data/extractor_data.txt', 'rt') as f:
        data = json.load(f)

    for domain in copy.copy(data):
        if domain in black_list:
            del data[domain]
            continue
        data[domain]["sum"] = 0
        # print(domain)
        # print(data[domain])
        for ip in data[domain]:
            data[domain]["sum"] += data[domain][ip]
        # print(data[domain]['sum'])
        for ip in copy.copy(data[domain]):
            if 'sum' != ip:
                if data[domain][ip] < 5000:
                    del data[domain][ip]


    d = OrderedDict()
    domain_sorted = sorted(data.items(), key=lambda x: x[1]['sum'], reverse=True)
    # pprint(domain_sorted)
    for domain in domain_sorted:
        ip_sorted = sorted(domain[1].items(), key=lambda  x: x[1], reverse=True)
        tmp = OrderedDict()
        for ip in ip_sorted:
            tmp[ip[0]] = ip[1]
        d[domain[0]] = tmp


    sum = 0
    for domain in copy.copy(d):
        del d[domain]['sum']
        sum += len(d[domain])
        if len(d[domain]) == 0:
            del d[domain]

    pprint(d)
    print(sum)
    with open("data_filtered.txt", 'wt') as f:
        json.dump(d, f)


if __name__ == '__main__':
    domain_handler()