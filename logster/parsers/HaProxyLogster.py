'''
A logster parser for haproxy log files in the HTTP format.
Reports percentiles for processing time and data sizes.
Accumulates by host and across backends.
'''

import os
import sys
import re
import math
import optparse
from collections import defaultdict

# unbuffered
#sys.stdout = os.fdopen(sys.stdout.fileno(), 'w', 0)
#sys.stderr = os.fdopen(sys.stderr.fileno(), 'w', 0)

# carbon metric prefix
PREFIX = 'haproxy'

# Should equal hostname on most platforms
NODENAME = os.uname()[1]

PERCENTILES = [0.100, 0.250, 0.500, 0.750, 0.900, 0.950, 0.990, 0.999]

# haproxy.<host>.<backend>.request.method
# haproxy.<host>.<backend>.response.code.<status>
#

from logster.logster_helper import MetricObject, LogsterParser
from logster.logster_helper import LogsterParsingException

from socket import socket, AF_UNIX, SOCK_STREAM

HaP_OK = 1
HaP_ERR = 2
HaP_SOCK_ERR = 3
HaP_BUFSIZE = 8192

class HaPConn(object):
    """HAProxy Socket object.
       This class abstract the socket interface so
       commands can be sent to HAProxy and results received and
       parse by the command objects"""

    def __init__(self, sfile):
        """Initializes an HAProxy and opens a connection to it
           sfile -> Path for the UNIX socket"""
        self.sfile = sfile
        self.sock = None
        self.open()

    def open(self):
        """Opens a connection for the socket.
           This function should only be called if
           self.closed() method was called"""

        self.sock = socket(AF_UNIX, SOCK_STREAM)
        self.sock.connect(self.sfile)

    def sendCmd(self, cmd, objectify=False):
        """Receives a command obj and sends it to the
           socket. Receives the output and passes it through
           the command to parse it a present it.
           - objectify -> Return an object instead of plain text"""
 
        res = ""
        self.sock.send(cmd.getCmd())
        output = self.sock.recv(HaP_BUFSIZE)

        while output:
            res += output
            output = self.sock.recv(HaP_BUFSIZE)

        if objectify:
            return cmd.getResultObj(res)

        return cmd.getResult(res)

    def close(self):
        """Closes the socket"""
        self.sock.close()

class Cmd(object):
    """Cmd - Command base class"""

    p_args = []
    args = {}
    cmdTxt = ""

    @classmethod
    def getCmd(self):

        # The default behavior is to apply the
        # args dict to cmdTxt
        return self.cmdTxt % self.args

    def getResult(self, res):
        """Returns raw results gathered from
           HAProxy"""
        return res

    def getResultObj(self, res):
        """Returns refined output from
           HAProxy, packed inside a Python obj
           i.e. a dict()"""
        return res

class showInfo(Cmd):
    """Show info HAProxy command"""
    cmdTxt = "show info\r\n"
    helpTxt = "Show info on HAProxy instance."

    def getResultObj(self, res):
        resDict = {}
        for line in res.split('\n'):
            k, v = line.split(':')
            resDict[k] = v

        return resDict

class baseStat(Cmd):
    def getCols(self, res):
        mobj = re.match("^# (?P<columns>.*)$", res, re.MULTILINE)

        if mobj:
            return dict((a, i) for i, a in enumerate(mobj.groupdict()['columns'].split(',')))
        raise Exception("Could not parse columns from HAProxy output")

class listStats(baseStat):
    """Show backend stats"""

    cmdTxt = "show stat\r\n"
    helpTxt = "Lists backend stats"

    def getResult(self, res):
        return "\n".join(self.getResultObj(res))

    def getResultObj(self, res):

        servers = []
        cols = self.getCols(res)

        for line in res.split('\n'):
            if not line.startswith('#') and len(line)>0:
                # Lines for server start with the name of the
                # backend.

                outCols = line.split(',')
                try:
                    # exclude frontend/backends without any backend servers
                    no_of_servers = int(outCols[cols['act']]) + int(outCols[cols['bck']]) + int(outCols[cols['chkdown']])
                    if (outCols[cols['svname']] == 'BACKEND') and (no_of_servers > 0):
                        servers.append(" " .join((
                             "Backend: %s" % outCols[cols['pxname']],
                             "SrvName: %s" % outCols[cols['svname']],
                             "Status: %s" % outCols[cols['status']],
                             "Weight: %s" %  outCols[cols['weight']],
                             "qCur: %s" % outCols[cols['qcur']],
                             "sCur: %s" % outCols[cols['scur']],
                             "eResp: %s" % outCols[cols['eresp']],
                             "cliAborts: %s" % outCols[cols['cli_abrt']],
                             "srvAborts: %s" % outCols[cols['srv_abrt']],
                             "bIn: %s" % outCols[cols['bin']],
                             "bOut: %s" % outCols[cols['bout']])))
                except Exception, e:
                    pass

        return servers

class PercentileMetric(MetricObject):
    '''PercentileMetric'''

    def __init__(self, size=1000, percentiles=None):
        self.track = []
        self.size = size
        if percentiles is None:
            self.percentiles = PERCENTILES
        else:
            self.percentiles = percentiles

    def add(self, value):
        '''add'''
        self.track.insert(0, float(value))

    def as_metrics(self, name):
        '''as_metrics'''
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
    '''HaProxyLogster'''

    patterns = []
    log_def = []
    regexs = []
    status_codes = defaultdict(lambda: defaultdict(lambda: 0))
    method = defaultdict(lambda: defaultdict(lambda: 0))
    response_time = defaultdict(PercentileMetric)
    prefix = PREFIX

    counters = defaultdict(lambda: 0)
    gauges = defaultdict(PercentileMetric)

    def build_pattern(self):
        '''build_pattern'''
        __rx = None
        __p = ""
        for i in self.patterns:
            __p = __p + i
            try:
                __rx = re.compile(__p)
            except Exception:
                #raise LogsterParsingException, "pattern compile failure: %s" % e
                print >> sys.stderr, "pattern compile failure: %s" % e
                sys.exit(2)
        return __rx

    def add_pattern(self, name, pattern, spacer=" ", leader=""):
        '''add_pattern'''
        self.patterns.append(r'{}(?P<{}>{}){}'.format(leader, name, pattern, spacer))
        self.log_def.append(name)

    def reset_pattern(self):
        '''reset_pattern'''
        self.patterns = []

    def extract_method(self, request):
        '''extract_method'''
        if request == '<BADREQ>':
            return 'BADREQ'
        else:
            return request

    def __init__(self, option_string=None):

        if option_string:
            options = option_string.split(' ')
        else:
            options = []

        optparser = optparse.OptionParser()
        optparser.add_option('--socket', '-s', dest='socket', default=None,
                            help='HaProxy Unix Socket')

        opts, args = optparser.parse_args(args=options)
 
        # Get/parse running haproxy config (frontends, backends, servers)
        # Plus info stat - session rate ....
        haproxy = HaPConn(opts.socket)
        cmd = showInfo
        ha_info = haproxy.sendCmd(cmd())
        haproxy.close()
        haproxy = HaPConn(opts.socket)
        cmd = listStats
        ha_stats = haproxy.sendCmd(cmd())
        haproxy.close()

        #consists of
        #Nov 29 14:26:47 localhost haproxy[14146]: '
        #Feb  1 14:26:47 localhost haproxy[14146]: '
        self.add_pattern('log_time', r'\S+( |  )\d+ \d+:\d+:\d+')
        self.add_pattern('hostname', r'\S+')
        self.add_pattern('process_id', r'\S+', ': ')

        # 67.22.131.95:39339 '
        self.add_pattern('client_ip', r'\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}', ':')
        self.add_pattern('client_port', r'\d+')

        #[29/Nov/2012:14:26:47.198] '
        self.add_pattern('accept_date', r'\[\S+\]')

        # www
        self.add_pattern('frontend_name', r'\S+')

        # normal/wwwA or www/<NOSRV>
        self.add_pattern('backend_name', r'\S+', '/')
        self.add_pattern('server_name', r'\S+')

        # 4/0/1/41/47
        self.add_pattern('Tq', r'[-+]?\d+', '/')
        self.add_pattern('Tw', r'[-+]?\d+', '/')
        self.add_pattern('Tc', r'[-+]?\d+', '/')
        self.add_pattern('Tr', r'[-+]?\d+', '/')
        self.add_pattern('Tt', r'[-+]?\d+')

        # 404 (-1 and 0 also seen in rare cases)
        self.add_pattern('status_code', r'(-1|0|\d{3})')

        # 10530 - If "option logasap" is specified, the
        # this value will be prefixed with a '+'
        self.add_pattern('bytes_read', r'[+]?\d+')
        self.bytes_read = PercentileMetric()

        # -
        self.add_pattern('captured_request_cookie', r'(-|\S+)')

        # -
        self.add_pattern('captured_response_cookie', r'(-|\S+)')

        # --NN
        self.add_pattern('term_event', r'\S', '')
        self.add_pattern('term_session', r'\S', '')
        self.add_pattern('client_cookie', r'\S', '')
        self.add_pattern('server_cookie', r'\S')

        # 392/391/13/1/0
        self.add_pattern('total_conns', r'\d+', '/')
        self.add_pattern('frontend_conns', r'\d+', '/')
        self.add_pattern('backend_conns', r'\d+', '/')
        self.add_pattern('srv_conns', r'\d+', '/')
        #This field may optionally be prefixed with a '+' sign,
        #indicating that the session has experienced a redispatch.
        self.add_pattern('retries', r'[+]?\d+')

        # 0/0
        self.add_pattern(r'server_queue', r'\d+', '/')
        self.add_pattern(r'backend_queue', r'\d+')
        # {||||Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.9.1.1) Gecko/20090715 Firefox/3.5.1}
        self.add_pattern('captured_request_headers', r'(\{.*\} |)', '')

        # {}
        self.add_pattern('captured_response_headers', r'(\{.*?\} |)', '')

        #"GET /goodiesbasket HTTP/1.1" or "<BADREQ>"
        # This final line might not be complete (truncated 1024 buffer)
        self.add_pattern('method', r'\S+', r'( |")', r'"')
        self.add_pattern('path', r'\S*', r'( |)')
        self.add_pattern('httpversion', r'.*?', r'("|)')

        # the final regex for HAProxy lines
        self.log_line_pattern = self.build_pattern()

        #
        # Up/Down log lines
        #
        self.reset_pattern()
        self.add_pattern('log_time', r'\S+( |  )\d+ \d+:\d+:\d+')
        self.add_pattern('hostname', r'\S+')
        self.add_pattern('process_id', r'\S+', ': ')

        # Server normal/wwwA or www/<NOSRV>
        self.add_pattern('backend_name', r'\S+', '/', 'Server ')
        self.add_pattern('server_name', r'\S+')

        #is UP/DOWN, reason:
        self.add_pattern('updown', r'\S+', ', ', 'is ')
        self.add_pattern('reason', r'[^,]+', ', ', 'reason: ')

        # skip the rest ...
        self.add_pattern('skipped', r'.*')
        self.updown_pattern = self.build_pattern()

        #
        # Start/Stop/Pause log lines
        #
        self.reset_pattern()
        # start/stop/pause haproxy
        self.add_pattern('log_time', r'\S+( |  )\d+ \d+:\d+:\d+')
        self.add_pattern('hostname', r'\S+')
        self.add_pattern('process_id', r'\S+', ': ')
        self.add_pattern('startstop', r'(Proxy \S+ started\.|Pausing proxy \S+\.|Stopping (backend|proxy) \S+ in \d+ \S+\.|Proxy \S+ stopped \([^)]+\)\.)', ': ')
        self.startstop_pattern = self.build_pattern()

        self.parsed_lines = 0
        self.unparsed_lines = 0

        # initialize counters - always send a value
        self.counters["{}.meta.parsed-lines.{}".format(self.prefix, NODENAME.replace(".", "-"))] = 0
        self.counters["{}.meta.unparsed-lines.{}".format(self.prefix, NODENAME.replace(".", "-"))] = 0
        self.counters["{}.meta.startstop.{}".format(self.prefix, NODENAME.replace(".", "-"))] = 0
        self.counters["{}.meta.up-down.down.{}".format(self.prefix, NODENAME.replace(".", "-"))] = 0
        self.counters["{}.meta.up-down.up.{}".format(self.prefix, NODENAME.replace(".", "-"))] = 0

    def parse_line(self, line):
        '''parse_line'''

        __m = self.log_line_pattern.match(line)
        if __m:
            __d = __m.groupdict()

            method = self.extract_method(__d['method'])
            self.increment("{}.meta.parsed-lines.{}".format(self.prefix, NODENAME.replace(".", "-")))

            for backend in ["backend." + __d['backend_name'], "all-backends"]:
                suffix = "{}.{}".format(NODENAME.replace(".", "-"), backend.replace(".", "-"))

                self.increment("{}.response.status.{}.{}".format(self.prefix, __d['status_code'], suffix))
                self.increment("{}.request.method.{}.{}".format(self.prefix, method.lower(), suffix))

                self.gauges["{}.bytesread-pct.{}.{}".format(self.prefix, "{}", suffix)].add(__d['bytes_read'])
                self.gauges["{}.request-time-pct.{}.{}".format(self.prefix, "{}", suffix)].add(__d['Tt'])

        else:
            __m = self.updown_pattern.match(line)
            if __m:
                __d = __m.groupdict()
                for backend in ["backend." + __d['backend_name'], "all-backends"]:
                    suffix = "{}.{}".format(NODENAME.replace(".", "-"), backend.replace(".", "-"))
                    if __d['updown'] == 'DOWN':
                        self.increment("{}.meta.up-down.down.{}".format(self.prefix, suffix))
                    elif __d['updown'] == 'UP':
                        self.increment("{}.meta.up-down.up.{}".format(self.prefix, suffix))
                    else:
                        print >> sys.stderr, 'Failed to parse line: %s' % line
                        self.increment("{}.meta.unparsed-lines.{}".format(self.prefix, NODENAME.replace(".", "-")))
            else:
                __m = self.startstop_pattern.match(line)
                if __m:
                    __d = __m.groupdict()
                    self.counters["{}.meta.startstop.{}".format(self.prefix, NODENAME.replace(".", "-"))] = 1
                else:
                    #raise LogsterParsingException, "Failed to parse line: %s" % line
                    print >> sys.stderr, 'Failed to parse line: %s' % line
                    self.increment("{}.meta.unparsed-lines.{}".format(self.prefix, NODENAME.replace(".", "-")))

    def increment(self, name):
        '''increment'''
        self.counters[name] += 1

    def get_state(self, duration):
        '''get_state'''
        metrics = []

        for name, value in self.counters.items():
            metrics.append(MetricObject(name, value))

        for name, value in self.gauges.items():
            metrics.extend(value.as_metrics(name))

        return metrics
