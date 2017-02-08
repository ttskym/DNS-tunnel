import numpy as np
from collections import deque
from scipy import stats


class Features:
    def __init__(self):
        self.flag = 1
        self.req_sizes = deque()
        self.res_sizes = deque()
        self.req_times = deque()
        self.res_times = deque()
        self.subdomains = deque()
        self.intervals = deque()
        self.query_type = deque()

    def req_size_average(self):
        return np.average(self.req_sizes)

    def req_size_var(self):
        return np.var(self.req_sizes)

    def interval_req_res_average(self):
        if len(self.res_times) != len(self.req_times):
            print("interval")
            exit("interval")
        if len(self.intervals) == 0:
            for item in zip(self.req_times, self.res_times):
                self.intervals.append(item[1] - item[0])
            # self.intervals = deque([item[1] - item[0] for item in zip(self.req_times, self.res_times)])
        elif len(self.intervals) != 20:
            self.intervals.append(self.res_times[-1] - self.req_times[-1])
        return np.average(self.intervals)

    def interval_req_res_var(self):
        if len(self.res_times) != len(self.req_times):
            print("interval")
            exit("interval")
        if len(self.intervals) == 0:
            for item in zip(self.req_times, self.res_times):
                self.intervals.append(item[1] - item[0])
            # self.intervals = deque([item[1] - item[0] for item in zip(self.req_times, self.res_times)])
        elif len(self.intervals) != 20:
            self.intervals.append(self.res_times[-1] - self.req_times[-1])
        return np.var(self.intervals)

    def entropy_unigram(self):
        len_sum = 0
        char_counter = {}
        for name in self.subdomains:
            len_sum += len(name)
            for ii in range(len(name)):
                if name[ii] in char_counter:
                    char_counter[name[ii]] += 1
                else:
                    char_counter[name[ii]] = 1
        pro = [char_counter[key]/len_sum for key in char_counter]
        # print(stats.entropy(pro))
        return stats.entropy(pro)

    def entropy_bigram(self):
        len_sum = 0
        bi_counter = {}
        for name in self.subdomains:
            len_sum += len(name) + 1
            name = '$'+name+'$'
            for i in range(len(name) - 2):
                if name[i:i+2] in bi_counter:
                    bi_counter[name[i:i+2]] += 1
                else:
                    bi_counter[name[i:i+2]] = 1
        pro = [bi_counter[key]/len_sum for key in bi_counter]
        # print(stats.entropy(pro))
        return stats.entropy(pro)

    def entropy_trigram(self):
        len_sum = 0
        tri_counter = {}
        for name in self.subdomains:
            len_sum += len(name)
            name = '$' + name + '$'
            for iii in range(len(name) - 3):
                if name[iii:iii+3] in tri_counter:
                    tri_counter[name[iii:iii + 3]] += 1
                else:
                    tri_counter[name[iii:iii + 3]] = 1
        pro = [tri_counter[key] / len_sum for key in tri_counter]
        return stats.entropy(pro)

    def interval_req(self):
        pass

    def ratio_size_req_res(self):
        pass

    def type(self):
        dns_type = {'1': 0,
                    '5': 0,
                    '15': 0,
                    '16': 0,
                    '10': 0,
                    '28': 0,
                    '2': 0,
                    '12': 0
                    }
        for code in self.query_type:
            if code in dns_type:
                dns_type[code] += 1
        return [dns_type[key]/len(self.query_type) for key in dns_type]

    def clear(self):
        self.req_sizes.clear()
        self.res_sizes.clear()
        self.req_times.clear()
        self.res_times.clear()
        self.subdomains.clear()
        # intervas is = the data computed not inserted, need to valid  ---> bug fixed
        if len(self.intervals) != 0:
            self.intervals.clear()
        self.query_type.clear()

    def clear_one(self):
        self.req_sizes.popleft()
        self.res_sizes.popleft()
        self.req_times.popleft()
        self.res_times.popleft()
        self.subdomains.popleft()
        if len(self.intervals) != 0:
            self.intervals.popleft()
        self.query_type.popleft()
