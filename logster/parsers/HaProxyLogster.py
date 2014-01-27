### A logster parser for haproxy log files in the HTTP format.
#  Reports percentiles for processing time and data sizes.
#  Accumulates by host and across backends.

import sys
import re
import inspect, traceback
import fileinput
import time
import heapq
from urlparse import urlparse
from functools import wraps
from pprint import pprint
from datetime import datetime
import math
from collections import defaultdict


# haproxy.<host>.<backend>.request.method
# haproxy.<host>.<backend>.response.code.<status>
#

from logster.logster_helper import MetricObject, LogsterParser
from logster.logster_helper import LogsterParsingException

class PercentileMetric(MetricObject):

    def __init__(self, size=1000, percentiles=[0.250, 0.500, 0.750, 0.900, 0.950, 0.990, 0.999]):
        self.track = []
        self.size = size
        self.percentiles = percentiles


    def add(self, value):
        self.track.insert(0, float(value))

    def asMetrics(self, name):
        #name = "{}.{}".format(name, "{}")

        metrics = []
        N = sorted(self.track)
        for pct in self.percentiles:
            k = (len(N)-1)*pct
            f = math.floor(k)
            c = math.ceil(k)
            if f == c:
                metrics.append(MetricObject(name.format(int(pct*1000)), N[int(k)], "{}th percentile".format(pct)))
                continue
            d0 = N[int(f)] * (c-k)
            d1 = N[int(c)] * (k-f)
            metrics.append(MetricObject(name.format(int(pct*1000)), d0+d1, "{}th percentile".format(pct)))

        if len(self.track) > self.size:
            self.track = self.track[:self.size]
        return metrics

class HaProxyLogster(LogsterParser):

    patterns = []
    log_def = []
    regexs = []
    status_codes = defaultdict(lambda: defaultdict(lambda: 0))
    method = defaultdict(lambda: defaultdict(lambda: 0))
    response_time = defaultdict(PercentileMetric)
    hostname = None

    counters = defaultdict(lambda: 0)
    gauges = defaultdict(PercentileMetric)

    def build_pattern(self):
        rx = None
        p = ""
        for i in self.patterns:
            p = p + i
            try:
                rx = re.compile(p)
            except Exception as e:
                print >> sys.stderr, self.log_def[i], "has failed", e
                sys.exit(1)
        return rx


    def add_pattern(self, name, pattern, spacer=" ", leader=""):
        self.patterns.append(r'{}(?P<{}>{}){}'.format(leader, name, pattern, spacer))
        self.log_def.append(name)


    def extract_method(self, request):
        if request == '<BADREQ>':
            return 'BADREQ'
        else:
            return request.split()[0]


    def __init__(self, option_string=None):
        #consists of
        #Nov 29 14:26:47 localhost haproxy[14146]: '
        self.add_pattern('log_time', '\S+ \d+ \d+:\d+:\d+')
        self.add_pattern('hostname', '\S+')
        self.add_pattern('process_id', '\S+')

        # 67.22.131.95:39339 '
        self.add_pattern('client_ip', '\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}', ':')
        self.add_pattern('client_port', '\d+')

        #[29/Nov/2012:14:26:47.198] '
        self.add_pattern('accept_date', '\[\S+\]')

        # www
        self.add_pattern('frontend_name', '\S+')

        # normal/wwwA
        self.add_pattern('backend_name','\S+', '/')
        self.add_pattern('server_name', '\S+')

        # 4/0/1/41/47
        self.add_pattern('Tq', '[-\d]+','/')
        self.add_pattern('Tw', '[-\d]+','/')
        self.add_pattern('Tc', '[-\d]+','/')
        self.add_pattern('Tr', '[-\d]+','/')
        self.add_pattern('Tt', '[-\d]+')

        # 404
        self.add_pattern('status_code', '\d{3}')

        # 10530
        self.add_pattern('bytes_read', '\d+')
        self.bytes_read = PercentileMetric()

        # -
        self.add_pattern('captured_request_cookie', '\S+')

        # -
        self.add_pattern('captured_response_cookie', '\S+')

        # --NN
        self.add_pattern('term_event', '\S', '')
        self.add_pattern('term_session', '\S', '')
        self.add_pattern('client_cookie', '\S', '')
        self.add_pattern('server_cookie', '\S')

        # 392/391/13/1/0
        self.add_pattern('total_conns', '\d+', '/')
        self.add_pattern('frontend_conns', '\d+', '/')
        self.add_pattern('backend_conns', '\d+', '/')
        self.add_pattern('srv_conns', '\d+', '/')
        self.add_pattern('retries', '\d+')

        # 0/0
        self.add_pattern(r'server_queue', '\d+', '/')
        self.add_pattern(r'backend_queue', '\d+')

        # {||||Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.9.1.1) Gecko/20090715 Firefox/3.5.1}
        self.add_pattern('captured_request_headers', '(\{.*\} |)', '')

        # {}
        self.add_pattern('captured_response_headers', '(\{.*?\} |)', '')

        #"GET /goodiesbasket HTTP/1.1"
        self.add_pattern('request', '.*', '"', '"')

        # the final regex for HAProxy lines
        self.log_line_pattern = self.build_pattern()

        self.parsed_lines = 0
        self.unparsed_lines = 0


    def parse_line(self, line):


        m = self.log_line_pattern.match(line)
        if m:
            d = m.groupdict()

            hostname = d['hostname']
            self.hostname = hostname
            method = self.extract_method(d['request'])
            self.increment("haproxy.meta.parsed-lines.{}".format(hostname.replace(".", "-")))

            for backend in ["backend."+d['backend_name'], "all-backends"]:
                prefix = "haproxy"
                suffix = "{}.{}".format(hostname.replace(".", "-"), backend.replace(".", "-"))

                self.increment("{}.response.status.{}.{}".format(prefix, d['status_code'], suffix))
                self.increment("{}.request.method.{}.{}".format(prefix, method.lower(), suffix))

                self.gauges["{}.bytesread-pct.{}.{}".format(prefix, "{}", suffix)].add(d['bytes_read'])
                self.gauges["{}.request-time-pct.{}.{}".format(prefix, "{}", suffix)].add(d['Tt'])

        else:
            if self.hostname:
                self.increment("haproxy.{}.meta.unparsed-lines".format(self.hostname))

    def increment(self, name):
        self.counters[name] += 1

    def get_state(self, duration):
        metrics = []

        for name, value in self.counters.items():
            metrics.append(MetricObject(name, value))

        for name, value in self.gauges.items():
            metrics.extend(value.asMetrics(name))

        return metrics
