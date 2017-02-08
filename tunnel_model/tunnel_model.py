import numpy as np
import tldextract
from collections import deque
from concurrent.futures import ProcessPoolExecutor
from scapy.all import *
from sklearn.externals import joblib
from sklearn.linear_model import SGDClassifier
from sklearn import svm
from sklearn import tree

from features import Features
import glob

# configuration
white_dir = '/home/ljk/dataset/white/valid/*'
black_dir = '/home/ljk/dataset/black/valid/*'
window_size = 10


num_white = 0
num_black = 0

X = []
Y = []

FILE = []
NO = []


def insert_data(req_res, feat_handler):
    feat_handler.req_sizes.append(req_res[0].len)
    feat_handler.res_sizes.append(req_res[1].len)
    feat_handler.req_times.append(req_res[0].time)
    feat_handler.res_times.append(req_res[1].time)
    feat_handler.query_type.append(str(req_res[0][DNSQR].qtype))

    # req_res[0][DNSQR].qname not req_res[0].qname ---> bug fixed
    tld = tldextract.extract(req_res[0][DNSQR].qname.decode())
    if tld.subdomain[-4:] == '.abc':
        subdomain = tld.subdomain[:-4]
    else:
        subdomain = tld.subdomain
    feat_handler.subdomains.append(subdomain)


def windows_handler(pkt_window, feat_handler, target_func):
    if feat_handler.flag == 1:
        for req_res in pkt_window:
            try:
                insert_data(req_res, feat_handler)
            except Exception as e:
                print(e)

        # window move 1
        feat_handler.flag = 0
    else:
        try:
            insert_data(pkt_window[-1], feat_handler)
        except Exception as e:
            print(e)

    try:
        x = [func() for func in target_func]
        # x.extend(feat_handler.type())

    except Exception as e:
        print('l1')
        print(e)

    # no window move 1
    # feat_handler.clear()
    # pkt_window.clear()

    # window move 1
    try:
        feat_handler.clear_one()
    except Exception as e:
        print(e)
    pkt_window.popleft()

    return x


def pcap_parser(file_name, flag):
    x = []
    y = []

    file = []
    no = []

    feat_handler = Features()

    req_size_average = feat_handler.req_size_average
    req_size_var = feat_handler.req_size_var
    interval_req_res_average = feat_handler.interval_req_res_average
    interval_req_res_var = feat_handler.interval_req_res_var
    entropy_unigram = feat_handler.entropy_unigram
    entropy_bigram = feat_handler.entropy_bigram
    entropy_trigram = feat_handler.entropy_trigram

    target_func = [interval_req_res_average,
                   # req_size_var,
                   # req_size_average,
                   # interval_req_res_var,
                   # entropy_unigram,
                   # entropy_bigram,
                   # entropy_trigram
                   ]
    # target_func = [req_size_var]

    window_num = 0
    pkt_window = deque()
    req = deque()
    res = dict()
    with PcapReader(file_name) as pkts:
        for pkt in pkts:
            try:
                if pkt.haslayer(DNS) and pkt.haslayer(DNSRR):
                    # print(file_name + " req window size --->" + str(len(req)))
                    # print(file_name + " res window size --->" + str(len(res)))
                    if req[0][DNS].id == pkt[DNS].id and req[0][UDP].sport == pkt[UDP].dport:
                        pkt_window.append((req.popleft(), pkt))
                        if len(pkt_window) == window_size:
                            x.append(windows_handler(pkt_window, feat_handler, target_func))
                            y.append(flag)
                            file.append(file_name)
                            no.append(window_num)
                            window_num += 1
                            # print(file_name + '=>' + str(window_num))

                        while True:
                            key = str(req[0][DNS].id)+str(req[0][UDP].sport)
                            if len(req) > 0 and res.get(key):
                                pkt_window.append((req.popleft(), res.pop(key)))
                                if len(pkt_window) == window_size:
                                    x.append(windows_handler(pkt_window, feat_handler, target_func,))
                                    y.append(flag)
                                    file.append(file_name)
                                    no.append(window_num)
                                    window_num += 1
                                    # print(file_name + '=>' + str(window_num))

                            else:
                                break
                    else:
                        key = str(pkt[DNS].id) + str(pkt[UDP].dport)
                        res[key] = pkt
                        if len(res) > 10:
                            req.popleft()
                        while True:
                            key = str(req[0][DNS].id)+str(req[0][UDP].sport)
                            if len(req) > 0 and res.get(key):
                                pkt_window.append((req.popleft(), res.pop(key)))
                                if len(pkt_window) == window_size:
                                    x.append(windows_handler(pkt_window, feat_handler, target_func,))
                                    y.append(flag)
                                    file.append(file_name)
                                    no.append(window_num)
                                    window_num += 1
                                    # print(file_name + '=>' + window_num)

                            else:
                                break

                elif pkt.haslayer(DNS) and pkt.haslayer(DNSRR) == 0:
                        req.append(pkt)
            except:
                continue
    # print(file_name)
    return x, y, file, no


def prepare_data():
    global num_black
    global num_white

    process_list = []

    with ProcessPoolExecutor() as pool:
        for file in glob.glob(white_dir):
            process_list.append(pool.submit(pcap_parser, file, 1))
        for process in process_list:
            x, y, file, no = process.result()
            X.extend(x)
            Y.extend(y)
            FILE.extend(file)
            NO.extend(no)
        process_list.clear()
        num_white = len(X)
        # print("x")
        # print(X)
        # print("y")
        # print(Y)
        print('begin black')
    with ProcessPoolExecutor() as pool:
        for file in glob.glob(black_dir):
            process_list.append(pool.submit(pcap_parser, file, 0))
        for process in process_list:
            x, y, file, no = process.result()
            X.extend(x)
            Y.extend(y)
            FILE.extend(file)
            NO.extend(no)
        num_black = len(X)-num_white

    print("white: " + str(num_white))
    print("black: " + str(num_black))


def train():
    prepare_data()
    #logisticl regression
    # clf = SGDClassifier(loss="log")
    # clf.fit(np.vstack(X), np.array(Y))

    # svm
    # clf = svm.SVC()
    # clf.fit(np.vstack(X), np.array(Y))
    #
    # Dicision Trees
    clf = tree.DecisionTreeClassifier()
    clf = clf.fit(np.vstack(X), np.array(Y))

    joblib.dump(clf, '/home/ljk/model/log.pkl')
    print(len(X))


def valid():
    prepare_data()
    clf = joblib.load('/home/ljk/model/log.pkl')
    result_pair = list(zip(list(clf.predict(X)), Y))
    num_true = 0
    num_false = 0
    TP = 0
    FP = 0
    for pair in result_pair:
        if pair[0] == pair[1]:
            num_true += 1
            if pair[1] == 0:
                TP += 1
        else:
            # print(FILE[num_true+num_false] + '---->' + str(NO[num_false + num_true]))
            # print(str(X[num_false + num_true]))
            num_false += 1
            if pair[0] == 0:
                FP += 1
    num = len(X)
    print("sum: " + str(num))
    print("accuracy: " + str(num_true/num))
    print("precision: " + str(TP/(TP+FP)))
    print("recall: " + str(TP/num_black))


if __name__ == "__main__":
    # train()
    valid()
