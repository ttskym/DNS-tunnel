import numpy as np


class Features:
    def __init__(self):
        self.req_sizes = []
        self.res_sizes = []
        self.req_times = []
        self.res_times = []
        self.subdomains = []
        self.intervals = []

    def req_size_average(self):
        return np.average(self.req_sizes)

    def req_size_var(self):
        return np.var(self.req_sizes)

    def interval_req_res_average(self):
        if len(self.res_times) != len(self.req_times):
            print("interval")
            exit("interval")
        if len(self.intervals) == 0:
            self.intervals = [item[1] - item[0] for item in zip(self.req_times, self.res_times)]
        return np.average(self.intervals)

    def interval_req_res_var(self):
        if len(self.res_times) != len(self.req_times):
            print("interval")
            exit("interval")
        if len(self.intervals) == 0:
            self.intervals = [item[1] - item[0] for item in zip(self.req_times, self.res_times)]
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
        self.intervals.clear()
