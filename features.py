import numpy as np
from collections import deque


class Features:
    def __init__(self):
        self.flag = 1
        self.req_sizes = deque()
        self.res_sizes = deque()
        self.req_times = deque()
        self.res_times = deque()
        self.subdomains = deque()
        self.intervals = deque()

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

    def character(self):
        pass

    def interval_req(self):
        pass

    def ratio_size_req_res(self):
        pass

    def type(self):
        pass

    def clear(self):
        self.req_sizes.clear()
        self.res_sizes.clear()
        self.req_times.clear()
        self.res_times.clear()
        self.subdomains.clear()
        # intervas is = the data computed not inserted, need to valid  ---> bug fixed
        if len(self.intervals) != 0:
            self.intervals.clear()

    def clear_one(self):
        self.req_sizes.popleft()
        self.res_sizes.popleft()
        self.req_times.popleft()
        self.res_times.popleft()
        self.subdomains.popleft()
        if len(self.intervals) != 0:
            self.intervals.popleft()
