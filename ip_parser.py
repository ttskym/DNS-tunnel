import urllib.request
import json


def taobao(ip):
    taobao_prefix = 'http://ip.taobao.com//service/getIpInfo.php?ip='
    url = taobao_prefix + ip
    try:
        with urllib.request.urlopen(url, timeout=10) as res:
            str_json = json.loads(res.read().decode())
            if str_json['code'] == 0:
                data = str_json['data']
                if data['region'].find('\u65b0\u7586') == -1:
                    print("**")
                print("%s : %s %s" % (data['ip'], data['region'], data['city']))
                return 0
            else:
                return 1
    except:
        return 1


def baidu(ip):
    baidu_prefix = 'http://api.map.baidu.com/location/ip?ak=fsABmM5rCw7um2G5WQU9EwFGL78ZWVEY&ip='
    url = baidu_prefix + ip
    try:
        with urllib.request.urlopen(url, timeout=10) as res:
            str_json = json.loads(res.read().decode())
            if str_json['status'] == 0:
                addr = str_json['content']['address_detail']
                if addr['province'].find('\u65b0\u7586') == -1:
                    print("**")
                print("%s : %s %s %s %s %s" % (ip, addr['province'], addr['city'], addr['district'], addr['street'], addr['street_number']))
                return 0
            else:
                return 1
    except:
        return 1


if __name__ == '__main__':
    #     with open('dns_name1.txt') as file:
    # lines = file.readlines()
    #     for line in lines:
    #         ip = line.split()[1]
    #         if baidu(ip) == 1:
    #             r = taobao(ip)
    #             if r == 1:
    #                 raise Exception



    with open("/Users/liujingkun/Exp/dns_tunneling/data/analyze_data/baidu_place",encoding="utf-8") as file:
        lines = iter(file.readlines())
        for line in lines:
            # print(line)
            if line.find(r'**') == 0:
                print(next(lines))
