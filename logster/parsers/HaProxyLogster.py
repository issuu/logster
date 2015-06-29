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
from ua_parser import user_agent_parser
from urlparse import urlparse
from IPy import IP

# unbuffered
#sys.stdout = os.fdopen(sys.stdout.fileno(), 'w', 0)
#sys.stderr = os.fdopen(sys.stderr.fileno(), 'w', 0)

# carbon metric prefix
PREFIX = 'haproxy'

# Should equal hostname on most platforms
NODENAME = os.uname()[1]

PERCENTILES = [0.100, 0.250, 0.500, 0.750, 0.900, 0.950, 0.990, 0.999]

# http://en.wikipedia.org/wiki/Hypertext_Transfer_Protocol
REQUEST_METHODS = ['GET','HEAD','POST','PUT','DELETE','TRACE','OPTIONS','CONNECT','PATCH']

# http://en.wikipedia.org/wiki/List_of_HTTP_status_codes
# The most common
STATUS_CODES = [200,204,206,301,302,304,400,401,403,404,405,408,410,416,500,502,503,504]

# Most common
LANGUAGES = ['en','es','pt','zh','ja','de','it','fr','ru','da','ar']

LINUX_VARIANTS = ['Linux', 'Ubuntu', 'Debian', 'Fedora', 'Gentoo', 'Red Hat', 'SUSE']

# In case we cannot detect the User-Agent use this crud detection of crawlers
BOT_PATTERN = re.compile('.*( Ezooms/|WinHttp\.WinHttpRequest|heritrix/|Java/|Python-urllib/|Siteimprove.com|Crawler|Bot|Spider|AndroidDownloadManager|URL2File/|Sentry/|Apache-HttpClient/|PHP/|Wget/|<\?php |(http://|\w+@)\w+(\.\w+)+)')
IMGPROXY_PATTERN = re.compile('.*\(via ggpht.com GoogleImageProxy\)')
PREVIEW_PATTERN = re.compile('.*Google Web Preview\)')

# /<account>/docs/<document>
ISSUUDOC_PATTERN = re.compile('^/[^/]+/docs($|/.+)')
ISSUUSTACKS_PATTERN = re.compile('^/[^/]+/stacks($|/.+)')
ISSUUFOLLOWERS_PATTERN = re.compile('^/[^/]+/followers($|/.+)')
ISSUUCALL_PATTERN = re.compile('^(/|/api/)(call|res)/(?P<subcall>[^/]+)/.+')
ISSUUHOME_PATTERN = re.compile('^/home/(?P<subhome>[^/]+)')
ISSUUQUERY_PATTERN = re.compile('^(/|/api/)query($|/.+)')
ISSUUSEARCH_PATTERN = re.compile('^/search($|/.+)')
ISSUUPUBLISH_PATTERN = re.compile('^/publish($|/.+)')
ISSUUEXPLORE_PATTERN = re.compile('^/explore($|/.+)')
ISSUUMULTIPART_PATTERN = re.compile('^/multipart($|/.+)')
ISSUUSIGNIN_PATTERN = re.compile('^/signin($|/.+)')
ISSUUSIGNUP_PATTERN = re.compile('^/signup($|/.+)')
ISSUUFBAPP_PATTERN = re.compile('^/_fbapp($|/.+)')
ISSUUPIXEL_PATTERN = re.compile('^/v1/(?P<pixel>[^?]*)')

# haproxy.<host>.<backend>.request.method
# haproxy.<host>.<backend>.response.code.<status>
#

from logster.logster_helper import MetricObject, LogsterParser
from logster.logster_helper import LogsterParsingException

from socket import socket, gethostbyname, AF_UNIX, SOCK_STREAM

HaP_OK = 1
HaP_ERR = 2
HaP_SOCK_ERR = 3
HaP_BUFSIZE = 8192

def resolveHost(host_or_ip):
    try:
        ip = IP(host_or_ip)
        return ip.strNormal()
    except:
        try:
            return gethostbyname(host_or_ip)
        except:
            return None

def getPreferredLocale(acceptLanguage):
    try:
        languages = acceptLanguage.split(",")
        locale_q_pairs = []
    
        for language in languages:
            if language.split(";")[0] == language:
                # no q => q = 1
                locale_q_pairs.append((language.strip(), "1"))
            else:
                locale = language.split(";")[0].strip()
                q = language.split(";")[1].split("=")[1]
                locale_q_pairs.append((locale, q))

        if len(locale_q_pairs) > 0:
            (l,q) = locale_q_pairs[0]
            # Disregard subtag
            return l.split('_')[0].split('-')[0].lower()
    except:
        pass
    return None

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
            try:
                k, v = line.split(':')
                resDict[k] = v.lstrip()
            except:
                pass

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

    def getResultObj(self, res):

        servers = []
        cols = self.getCols(res)

        for line in res.split('\n'):
            if not line.startswith('#') and len(line)>0:
                # Lines for server start with the name of the
                # backend.

                outCols = line.split(',')
                try:
                    if outCols[cols['svname']] == 'BACKEND':
                        # exclude frontend/backends without any backend servers
                        no_of_servers = int(outCols[cols['act']]) + int(outCols[cols['bck']]) + int(outCols[cols['chkdown']])
                    if (outCols[cols['svname']] == 'BACKEND' and no_of_servers > 0) or (outCols[cols['svname']] == 'FRONTEND'):
                        servers.append({
                              'backend':   outCols[cols['pxname']],
                              'srvname':   outCols[cols['svname']],
                              'status':    outCols[cols['status']],
                              'weight':    outCols[cols['weight']],
                              'qcur':      outCols[cols['qcur']],
                              'qmax':      outCols[cols['qmax']],
                              'scur':      outCols[cols['scur']],
                              'smax':      outCols[cols['smax']],
                              'rate':      outCols[cols['rate']],
                              'ratemax':   outCols[cols['rate_max']],
                              'retries':   outCols[cols['wretr']],
                              'eresp':     outCols[cols['eresp']],
                              'cliaborts': outCols[cols['cli_abrt']],
                              'srvaborts': outCols[cols['srv_abrt']],
                              'bin':       outCols[cols['bin']],
                              'bout':      outCols[cols['bout']]})
                except:
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

    ip_counter = {}
    patterns = []
    log_def = []
    regexs = []
    status_codes = defaultdict(lambda: defaultdict(lambda: 0))
    method = defaultdict(lambda: defaultdict(lambda: 0))
    response_time = defaultdict(PercentileMetric)
    prefix = PREFIX
    nodename = NODENAME.replace(".", "-")

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
        elif request.upper() in REQUEST_METHODS:
            return request
        else:
            return 'OTHER'

    def extract_status_code(self, status_code):
        '''extract_status_code'''
        try:
            sc = int(status_code)
            if sc in STATUS_CODES:
                return str(sc)
            elif sc >= 100 and sc < 600:
                return 'OTHER'
            else:
                return 'BADREQ'
        except:
            return 'BADREQ'

    def __init__(self, option_string=None):

        if option_string:
            options = option_string.split(' ')
        else:
            options = []

        optparser = optparse.OptionParser()
        optparser.add_option('--socket', '-s', dest='pxy_socket', default=None,
                            help='HaProxy Unix Socket')
        optparser.add_option('--headers', '-x', dest='headers', default=None,
                            help='HaProxy Captured Request Headers in a comma separated list')
        optparser.add_option('--crawlerhosts', '-c', dest='crawlerhosts', default=None,
                            help="Comma separated list of known crawlerhost's/ip's, i.e. findthatfile.com,63.208.194.130")
        optparser.add_option('--issuudocs', '-i', dest='issuudocs', action="store_true", default=False,
                            help='Special parsing the request to detect Issuu document path, i.e. /<account>/docs/<document>')
        optparser.add_option('--xffip', '-f', dest='usexffip', action="store_true", default=False,
                            help='Use X-Forwarded-For value for the client-ip (useful if behind another proxy like ELB)')

        opts, args = optparser.parse_args(args=options)

        self.issuudocs = opts.issuudocs
        self.usexffip = opts.usexffip
        self.headers = None
        if opts.headers:
            self.headers = [x.lower() for x in opts.headers.split(',')]
 
        self.crawlerips = []
        if opts.crawlerhosts:
            self.crawlerips = [resolveHost(x) for x in opts.crawlerhosts.split(',')]
 
        if opts.pxy_socket is None:
            print >> sys.stderr, 'Missing --socket option'
            raise Exception("Missing --socket option")
            
        # Get/parse running haproxy config (frontends, backends, servers)
        # Plus info stat - session rate ....
        haproxy = HaPConn(opts.pxy_socket)
        cmd = showInfo
        ha_info = haproxy.sendCmd(cmd(), objectify=True)
        haproxy.close()
        haproxy = HaPConn(opts.pxy_socket)
        cmd = listStats
        ha_stats = haproxy.sendCmd(cmd(), objectify=True)
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
        self.add_pattern('captured_request_headers', r'([^}]*|)', r'(\} |)', r'(\{|)')

        # {}
        self.add_pattern('captured_response_headers', r'([^}]*|)', r'(\} |)', r'(\{|)')

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
        self.add_pattern('skipped', r'.*','')
        self.updown_pattern = self.build_pattern()

        #
        # Start/Stop/Pause log lines
        #
        self.reset_pattern()
        # start/stop/pause haproxy
        self.add_pattern('log_time', r'\S+( |  )\d+ \d+:\d+:\d+')
        self.add_pattern('hostname', r'\S+')
        self.add_pattern('process_id', r'\S+', ': ')
        self.add_pattern('startstop', r'(Proxy \S+ started\.|Pausing proxy \S+\.|Stopping (backend|proxy) \S+ in \d+ \S+\.|Proxy \S+ stopped \([^)]+\)\.)','')
        self.startstop_pattern = self.build_pattern()

        #
        # no server available
        #
        self.reset_pattern()
        # start/stop/pause haproxy
        self.add_pattern('log_time', r'\S+( |  )\d+ \d+:\d+:\d+')
        self.add_pattern('hostname', r'\S+')
        self.add_pattern('process_id', r'\S+', ': ')
        self.add_pattern('backend_name', r'\S+', ' ', 'backend ')
        # skip the rest ...
        self.add_pattern('skipped', r'.*','', 'has no server available!')
        self.noserver_pattern = self.build_pattern()

        self.parsed_lines = 0
        self.unparsed_lines = 0

        # initialize counters - always send a value
        self.counters["{}.meta.parsed-lines.{}".format(self.prefix, self.nodename)] = 0
        self.counters["{}.meta.unparsed-lines.{}".format(self.prefix, self.nodename)] = 0
        self.counters["{}.meta.start-stop.{}".format(self.prefix, self.nodename)] = 0

        self.counters["{}.stats.cur-conns.{}".format(self.prefix, self.nodename)] = int(ha_info['CurrConns'])
        self.counters["{}.stats.tasks.{}".format(self.prefix, self.nodename)] = int(ha_info['Tasks'])
        self.counters["{}.stats.run-queue.{}".format(self.prefix, self.nodename)] = int(ha_info['Run_queue'])

        self.counters["{}.request.internal.{}".format(self.prefix, self.nodename)] = 0
        self.counters["{}.request.external.{}".format(self.prefix, self.nodename)] = 0
        self.counters["{}.request.tarpit.{}".format(self.prefix, self.nodename)] = 0
        self.counters["{}.request.block.{}".format(self.prefix, self.nodename)] = 0

        if self.issuudocs:
            for u in ["root","docs","stacks","followers","search","publish","explore","api-query","multipart","signin","signup","fbapp"]:
                self.counters["{}.request.url.{}.crawlers.{}".format(self.prefix, u, self.nodename)] = 0
                self.counters["{}.request.url.{}.crawlers.3xx.{}".format(self.prefix, u, self.nodename)] = 0
                self.counters["{}.request.url.{}.crawlers.4xx.{}".format(self.prefix, u, self.nodename)] = 0
                self.counters["{}.request.url.{}.crawlers.5xx.{}".format(self.prefix, u, self.nodename)] = 0
                self.counters["{}.request.url.{}.non-crawlers.{}".format(self.prefix, u, self.nodename)] = 0
                self.counters["{}.request.url.{}.non-crawlers.3xx.{}".format(self.prefix, u, self.nodename)] = 0
                self.counters["{}.request.url.{}.non-crawlers.4xx.{}".format(self.prefix, u, self.nodename)] = 0
                self.counters["{}.request.url.{}.non-crawlers.5xx.{}".format(self.prefix, u, self.nodename)] = 0

        if self.headers:
            if 'user-agent' in self.headers:
                self.counters["{}.stats.browser.ua.crawlers.{}".format(self.prefix, self.nodename)] = 0
                self.counters["{}.stats.browser.ua.crawlers.real.{}".format(self.prefix, self.nodename)] = 0
                self.counters["{}.stats.browser.ua.crawlers.googlebot.{}".format(self.prefix, self.nodename)] = 0
                self.counters["{}.stats.browser.ua.crawlers.bingbot.{}".format(self.prefix, self.nodename)] = 0
                self.counters["{}.stats.browser.ua.crawlers.yahoo.{}".format(self.prefix, self.nodename)] = 0
                self.counters["{}.stats.browser.ua.crawlers.baiduspider.{}".format(self.prefix, self.nodename)] = 0
                self.counters["{}.stats.browser.ua.crawlers.yandex.{}".format(self.prefix, self.nodename)] = 0
                self.counters["{}.stats.browser.ua.crawlers.ips.{}".format(self.prefix, self.nodename)] = 0
                self.counters["{}.stats.browser.ua.crawlers.empty-ua.{}".format(self.prefix, self.nodename)] = 0
                self.counters["{}.stats.browser.ua.os.windows-phone.{}".format(self.prefix, self.nodename)] = 0
                self.counters["{}.stats.browser.ua.os.windows.{}".format(self.prefix, self.nodename)] = 0
                self.counters["{}.stats.browser.ua.os.ios.{}".format(self.prefix, self.nodename)] = 0
                self.counters["{}.stats.browser.ua.os.android.{}".format(self.prefix, self.nodename)] = 0
                self.counters["{}.stats.browser.ua.os.mac-os-x.{}".format(self.prefix, self.nodename)] = 0
                self.counters["{}.stats.browser.ua.os.linux.{}".format(self.prefix, self.nodename)] = 0
                self.counters["{}.stats.browser.ua.os.blackberry.{}".format(self.prefix, self.nodename)] = 0
                self.counters["{}.stats.browser.ua.os.other.{}".format(self.prefix, self.nodename)] = 0
                self.counters["{}.stats.browser.ua.imgproxy.{}".format(self.prefix, self.nodename)] = 0
                self.counters["{}.stats.browser.ua.preview.{}".format(self.prefix, self.nodename)] = 0
                self.counters["{}.stats.browser.ua.imgproxy.google.{}".format(self.prefix, self.nodename)] = 0
                self.counters["{}.stats.browser.ua.preview.google.{}".format(self.prefix, self.nodename)] = 0

                self.counters["{}.response.status.crawlers.4xx.{}".format(self.prefix, self.nodename)] = 0
                self.counters["{}.response.status.crawlers.5xx.{}".format(self.prefix, self.nodename)] = 0

            if 'accept-language' in self.headers:
                for lang in ['OTHER']+LANGUAGES:
                    self.counters["{}.stats.browser.language.{}.{}".format(self.prefix, lang.lower(), self.nodename)] = 0

            if 'dnt' in self.headers:
                self.counters["{}.stats.browser.dnt.true.{}".format(self.prefix, self.nodename)] = 0
                self.counters["{}.stats.browser.dnt.false.{}".format(self.prefix, self.nodename)] = 0
                self.counters["{}.stats.browser.dnt.other.{}".format(self.prefix, self.nodename)] = 0
                self.counters["{}.stats.browser.dnt.crawler.{}".format(self.prefix, self.nodename)] = 0
                self.counters["{}.stats.browser.dnt.unset.{}".format(self.prefix, self.nodename)] = 0

        # for each known backend - initialize counters
        for backend in map(lambda x: "backend-"+x['backend'], filter(lambda y: y['srvname'] == 'BACKEND', ha_stats)) + ["all-backends"]:
            suffix = "{}.{}".format(self.nodename, backend.replace(".", "-"))
            for method in ['BADREQ','OTHER']+REQUEST_METHODS:
                self.counters["{}.request.method.{}.{}".format(self.prefix, method.lower(), suffix)] = 0
            for status_code in [str(x) for x in STATUS_CODES] + ['BADREQ','OTHER']:
                self.counters["{}.response.clientabort.status.{}.{}".format(self.prefix, status_code.lower(), suffix)] = 0
                self.counters["{}.response.status.{}.{}".format(self.prefix, status_code.lower(), suffix)] = 0
            self.counters["{}.meta.up-down.{}".format(self.prefix, suffix)] = 0
            self.counters["{}.meta.noserver.{}".format(self.prefix, suffix)] = 0
            self.counters["{}.stats.backend.ip-variance.{}".format(self.prefix, suffix)] = 0
            self.ip_counter[backend] = {}
        for haproxy in filter(lambda y: y['srvname'] == 'BACKEND', ha_stats):
            suffix = "{}.{}".format(self.nodename, "backend-"+haproxy['backend'].replace(".", "-"))
            self.counters["{}.stats.backend.queue.{}".format(self.prefix, suffix)] = haproxy['qcur']
            self.counters["{}.stats.backend.session-rate.{}".format(self.prefix, suffix)] = haproxy['rate']
            self.counters["{}.stats.backend.sessions.{}".format(self.prefix, suffix)] = haproxy['scur']
            self.counters["{}.stats.backend.error-response.{}".format(self.prefix, suffix)] = haproxy['eresp']
            self.counters["{}.stats.backend.client-aborts.{}".format(self.prefix, suffix)] = haproxy['cliaborts']
            self.counters["{}.stats.backend.server-aborts.{}".format(self.prefix, suffix)] = haproxy['srvaborts']
        for haproxy in filter(lambda y: y['srvname'] == 'FRONTEND', ha_stats):
            suffix = "{}.{}".format(self.nodename, "frontend-"+haproxy['backend'].replace(".", "-"))
            self.counters["{}.stats.frontend.queue.{}".format(self.prefix, suffix)] = haproxy['qcur']
            self.counters["{}.stats.frontend.session-rate.{}".format(self.prefix, suffix)] = haproxy['rate']
            self.counters["{}.stats.frontend.sessions.{}".format(self.prefix, suffix)] = haproxy['scur']

    def parse_line(self, line):
        '''parse_line'''

        __m = self.log_line_pattern.match(line)
        if __m:
            __d = __m.groupdict()

            method = self.extract_method(__d['method'])
            status_code = self.extract_status_code(__d['status_code'])
            tarpit   = __d['term_event']=='P' and __d['term_session']=='T'
            block    = __d['term_event']=='P' and __d['term_session']=='R'
            # annoying chinese sites causing 503s because of client aborts
            cc_event = __d['term_event']=='C' and __d['term_session']=='C'

            if tarpit:
                # Do not process any further iff tarpit
                self.increment("{}.request.tarpit.{}".format(self.prefix, self.nodename))
                return

            if block:
                # Do not process any further iff block
                self.increment("{}.request.block.{}".format(self.prefix, self.nodename))
                return

            try:
                sc = int(status_code)
            except:
                sc = -1

            ua  = None
            al  = None
            dnt = None
            xff = None
            if self.headers and __d['captured_request_headers']:
                crhs = __d['captured_request_headers'].split('|')
                if len(crhs) == len(self.headers):
                    for i in range(len(crhs)):
                        __d['crh_'+self.headers[i]] = crhs[i]

                    if 'crh_user-agent' in __d:
                        if __d['crh_user-agent']:
                            try:
                                ua = user_agent_parser.Parse(__d['crh_user-agent'].replace('User-Agent: ','',1))
                            except:
                                pass
                    if 'crh_accept-language' in __d:
                        if __d['crh_accept-language']:
                            al = getPreferredLocale(__d['crh_accept-language'])
                    if 'crh_x-forwarded-for' in __d:
                        if __d['crh_x-forwarded-for']:
                            try:
                                xff = __d['crh_x-forwarded-for'].split(',')[-1].strip()
                            except:
                                pass
                    if 'crh_dnt' in __d:
                        if __d['crh_dnt']:
                            dnt = __d['crh_dnt']

            try:
                if xff and self.usexffip:
                    client_ip = IP(xff)
                else:
                    client_ip = IP(__d['client_ip'])
                    if client_ip in IP('127.0.0.0/8') and xff:
                        client_ip = IP(xff)
            except:
                # This should in theory never happen
                client_ip = IP('127.0.0.1')

            self.increment("{}.meta.parsed-lines.{}".format(self.prefix, self.nodename))

            if client_ip.iptype() != 'PRIVATE':
                self.increment("{}.request.external.{}".format(self.prefix, self.nodename))
            else:
                self.increment("{}.request.internal.{}".format(self.prefix, self.nodename))

            # Detect/Handle Spiders/Crawlers
            is_spider = False
            is_img_proxy = False
            is_preview_browser = False

            if client_ip.strNormal() in self.crawlerips:
                is_spider = True
            elif ua:
                try:
                    # Spider
                    if ua['device']['family'] == 'Spider':
                        is_spider = True
                    elif ua['device']['family'] == 'Other' and BOT_PATTERN.match(ua['string']):
                        is_spider = True
                    elif ua['device']['family'] == 'Other' and IMGPROXY_PATTERN.match(ua['string']):
                        is_img_proxy = True
                    elif ua['device']['family'] == 'Other' and PREVIEW_PATTERN.match(ua['string']):
                        is_preview_browser = True
                    else:
                        # OS Family, i.e. Windows 7, Windows 2000, iOS, Android, Mac OS X, Windows Phone, Windows Mobile
                        os_family=ua['os']['family']
                        os_familyname=os_family.split(' ')[0]
                        if os_familyname == 'Windows':
                            if os_family in ['Windows Phone', 'Windows Mobile']:
                                self.increment("{}.stats.browser.ua.os.windows-phone.{}".format(self.prefix, self.nodename))
                            else:
                                self.increment("{}.stats.browser.ua.os.windows.{}".format(self.prefix, self.nodename))
                        elif os_family == 'iOS':
                            self.increment("{}.stats.browser.ua.os.ios.{}".format(self.prefix, self.nodename))
                        elif os_family == 'Android':
                            self.increment("{}.stats.browser.ua.os.android.{}".format(self.prefix, self.nodename))
                        elif os_family in ['Mac OS X', 'Mac OS']:
                            self.increment("{}.stats.browser.ua.os.mac-os-x.{}".format(self.prefix, self.nodename))
                        elif os_family in LINUX_VARIANTS:
                            self.increment("{}.stats.browser.ua.os.linux.{}".format(self.prefix, self.nodename))
                        elif os_familyname == 'BlackBerry':
                            self.increment("{}.stats.browser.ua.os.blackberry.{}".format(self.prefix, self.nodename))
                        else:
                            self.increment("{}.stats.browser.ua.os.other.{}".format(self.prefix, self.nodename))
                except:
                    self.increment("{}.stats.browser.ua.os.other.{}".format(self.prefix, self.nodename))
            elif ua is None and 'crh_user-agent' in __d and client_ip.iptype() != 'PRIVATE':
                # Empty User-Agent string and none private network - mark it as a spider
                is_spider = True

            if is_spider:
                self.increment("{}.stats.browser.ua.crawlers.{}".format(self.prefix, self.nodename))
                if ua:
                    self.increment("{}.stats.browser.ua.crawlers.real.{}".format(self.prefix, self.nodename))
                    try:
                        if ua['user_agent']['family'] == 'Googlebot' or 'Googlebot' in ua['string']:
                            self.increment("{}.stats.browser.ua.crawlers.googlebot.{}".format(self.prefix, self.nodename))
                        elif 'bingbot' in ua['string']:
                            self.increment("{}.stats.browser.ua.crawlers.bingbot.{}".format(self.prefix, self.nodename))
                        elif 'Yahoo! Slurp' in ua['string']:
                            self.increment("{}.stats.browser.ua.crawlers.yahoo.{}".format(self.prefix, self.nodename))
                        elif 'Baiduspider' in ua['string']:
                            self.increment("{}.stats.browser.ua.crawlers.baiduspider.{}".format(self.prefix, self.nodename))
                        elif 'YandexBot' in ua['string']:
                            self.increment("{}.stats.browser.ua.crawlers.yandex.{}".format(self.prefix, self.nodename))
                    except:
                        pass
                elif client_ip.strNormal() in self.crawlerips:
                    self.increment("{}.stats.browser.ua.crawlers.ips.{}".format(self.prefix, self.nodename))
                else:
                    self.increment("{}.stats.browser.ua.crawlers.empty-ua.{}".format(self.prefix, self.nodename))
                if sc >= 400 and sc <= 499:
                    self.increment("{}.response.status.crawlers.4xx.{}".format(self.prefix, self.nodename))
                elif sc >= 500 and sc <= 599:
                    self.increment("{}.response.status.crawlers.5xx.{}".format(self.prefix, self.nodename))

            if is_img_proxy:
                self.increment("{}.stats.browser.ua.imgproxy.{}".format(self.prefix, self.nodename))
                if ua:
                    try:
                        if 'GoogleImageProxy' in ua['string']:
                            self.increment("{}.stats.browser.ua.imgproxy.google.{}".format(self.prefix, self.nodename))
                    except:
                        pass

            if is_preview_browser:
                self.increment("{}.stats.browser.ua.preview.{}".format(self.prefix, self.nodename))
                if ua:
                    try:
                        if 'Google' in ua['string']:
                            self.increment("{}.stats.browser.ua.preview.google.{}".format(self.prefix, self.nodename))
                    except:
                        pass

            if al and not is_spider and not is_img_proxy and not is_preview_browser:
                if al in LANGUAGES:
                    self.increment("{}.stats.browser.language.{}.{}".format(self.prefix, al.lower(), self.nodename))
                else:
                    self.increment("{}.stats.browser.language.{}.{}".format(self.prefix, 'other', self.nodename))

            if dnt:
                if not is_spider and not is_img_proxy and not is_preview_browser:
                    if dnt in ["1","TRUE","True","true"]:
                        self.increment("{}.stats.browser.dnt.true.{}".format(self.prefix, self.nodename))
                    elif dnt in ["0","FALSE","False","false"]:
                        self.increment("{}.stats.browser.dnt.false.{}".format(self.prefix, self.nodename))
                    else:
                        self.increment("{}.stats.browser.dnt.other.{}".format(self.prefix, self.nodename))
                else:
                    self.increment("{}.stats.browser.dnt.crawler.{}".format(self.prefix, self.nodename))
            elif self.headers and 'dnt' in self.headers:
                self.increment("{}.stats.browser.dnt.unset.{}".format(self.prefix, self.nodename))

            if not is_spider and not is_img_proxy and not is_preview_browser:
                if client_ip.iptype() != 'PRIVATE' and __d['backend_name'] != 'statistics':
                    if __d['server_name'] != '<NOSRV>':
                        try:
                            self.ip_counter['backend-'+__d['backend_name']][client_ip.ip] += 1
                        except:
                            self.ip_counter['backend-'+__d['backend_name']][client_ip.ip] = 1
                    try:
                        self.ip_counter['all-backends'][client_ip.ip] += 1
                    except:
                        self.ip_counter['all-backends'][client_ip.ip] = 1

            # skip redirects
            if self.issuudocs and sc > 0:
                try:
                    __iu = urlparse(__d['path'])
                    if ISSUUDOC_PATTERN.match(__iu.path):
                        if is_spider:
                            if cc_event:
                                self.increment("{}.request.url.docs.crawlers.clientabort.status.{}.{}".format(self.prefix, status_code.lower(), self.nodename))
                            else:
                                self.increment("{}.request.url.docs.crawlers.{}".format(self.prefix, self.nodename))
                                if sc >= 300 and sc <= 399:
                                    self.increment("{}.request.url.docs.crawlers.3xx.{}".format(self.prefix, self.nodename))
                                    self.gauges["{}.request.url.docs.crawlers.3xx.time-pct.{}.{}".format(self.prefix, "{}", self.nodename)].add(__d['Tt'])
                                    if __d['Tr'] > 0:
                                        self.gauges["{}.request.url.docs.crawlers.3xx.server-time-pct.{}.{}".format(self.prefix, "{}", self.nodename)].add(__d['Tr'])
                                else:
                                    if sc >= 400 and sc <= 499:
                                        self.increment("{}.request.url.docs.crawlers.4xx.{}".format(self.prefix, self.nodename))
                                    elif sc >= 500 and sc <= 599:
                                        self.increment("{}.request.url.docs.crawlers.5xx.{}".format(self.prefix, self.nodename))
                                    self.gauges["{}.request.url.docs.crawlers.time-pct.{}.{}".format(self.prefix, "{}", self.nodename)].add(__d['Tt'])
                                    if __d['Tr'] > 0:
                                        self.gauges["{}.request.url.docs.crawlers.server-time-pct.{}.{}".format(self.prefix, "{}", self.nodename)].add(__d['Tr'])
                        else:
                            if cc_event:
                                self.increment("{}.request.url.docs.non-crawlers.clientabort.status.{}.{}".format(self.prefix, status_code.lower(), self.nodename))
                            else:
                                self.increment("{}.request.url.docs.non-crawlers.{}".format(self.prefix, self.nodename))
                                if sc >= 300 and sc <= 399:
                                    self.increment("{}.request.url.docs.non-crawlers.3xx.{}".format(self.prefix, self.nodename))
                                    self.gauges["{}.request.url.docs.non-crawlers.3xx.time-pct.{}.{}".format(self.prefix, "{}", self.nodename)].add(__d['Tt'])
                                    if __d['Tr'] > 0:
                                        self.gauges["{}.request.url.docs.non-crawlers.3xx.server-time-pct.{}.{}".format(self.prefix, "{}", self.nodename)].add(__d['Tr'])
                                else:
                                    if sc >= 400 and sc <= 499:
                                        self.increment("{}.request.url.docs.non-crawlers.4xx.{}".format(self.prefix, self.nodename))
                                    elif sc >= 500 and sc <= 599:
                                        self.increment("{}.request.url.docs.non-crawlers.5xx.{}".format(self.prefix, self.nodename))
                                    self.gauges["{}.request.url.docs.non-crawlers.time-pct.{}.{}".format(self.prefix, "{}", self.nodename)].add(__d['Tt'])
                                    if __d['Tr'] > 0:
                                        self.gauges["{}.request.url.docs.non-crawlers.server-time-pct.{}.{}".format(self.prefix, "{}", self.nodename)].add(__d['Tr'])
                    elif ISSUUSTACKS_PATTERN.match(__iu.path):
                        if is_spider:
                            if cc_event:
                                self.increment("{}.request.url.stacks.crawlers.clientabort.status.{}.{}".format(self.prefix, status_code.lower(), self.nodename))
                            else:
                                self.increment("{}.request.url.stacks.crawlers.{}".format(self.prefix, self.nodename))
                                if sc >= 300 and sc <= 399:
                                    self.increment("{}.request.url.stacks.crawlers.3xx.{}".format(self.prefix, self.nodename))
                                    self.gauges["{}.request.url.stacks.crawlers.3xx.time-pct.{}.{}".format(self.prefix, "{}", self.nodename)].add(__d['Tt'])
                                    if __d['Tr'] > 0:
                                        self.gauges["{}.request.url.stacks.crawlers.3xx.server-time-pct.{}.{}".format(self.prefix, "{}", self.nodename)].add(__d['Tr'])
                                else:
                                    if sc >= 400 and sc <= 499:
                                        self.increment("{}.request.url.stacks.crawlers.4xx.{}".format(self.prefix, self.nodename))
                                    elif sc >= 500 and sc <= 599:
                                        self.increment("{}.request.url.stacks.crawlers.5xx.{}".format(self.prefix, self.nodename))
                                    self.gauges["{}.request.url.stacks.crawlers.time-pct.{}.{}".format(self.prefix, "{}", self.nodename)].add(__d['Tt'])
                                    if __d['Tr'] > 0:
                                        self.gauges["{}.request.url.stacks.crawlers.server-time-pct.{}.{}".format(self.prefix, "{}", self.nodename)].add(__d['Tr'])
                        else:
                            if cc_event:
                                self.increment("{}.request.url.stacks.non-crawlers.clientabort.status.{}.{}".format(self.prefix, status_code.lower(), self.nodename))
                            else:
                                self.increment("{}.request.url.stacks.non-crawlers.{}".format(self.prefix, self.nodename))
                                if sc >= 300 and sc <= 399:
                                    self.increment("{}.request.url.stacks.non-crawlers.3xx.{}".format(self.prefix, self.nodename))
                                    self.gauges["{}.request.url.stacks.non-crawlers.3xx.time-pct.{}.{}".format(self.prefix, "{}", self.nodename)].add(__d['Tt'])
                                    if __d['Tr'] > 0:
                                        self.gauges["{}.request.url.stacks.non-crawlers.3xx.server-time-pct.{}.{}".format(self.prefix, "{}", self.nodename)].add(__d['Tr'])
                                else:
                                    if sc >= 400 and sc <= 499:
                                        self.increment("{}.request.url.stacks.non-crawlers.4xx.{}".format(self.prefix, self.nodename))
                                    elif sc >= 500 and sc <= 599:
                                        self.increment("{}.request.url.stacks.non-crawlers.5xx.{}".format(self.prefix, self.nodename))
                                    self.gauges["{}.request.url.stacks.non-crawlers.time-pct.{}.{}".format(self.prefix, "{}", self.nodename)].add(__d['Tt'])
                                    if __d['Tr'] > 0:
                                        self.gauges["{}.request.url.stacks.non-crawlers.server-time-pct.{}.{}".format(self.prefix, "{}", self.nodename)].add(__d['Tr'])
                    elif ISSUUFOLLOWERS_PATTERN.match(__iu.path):
                        if is_spider:
                            if cc_event:
                                self.increment("{}.request.url.followers.crawlers.clientabort.status.{}.{}".format(self.prefix, status_code.lower(), self.nodename))
                            else:
                                self.increment("{}.request.url.followers.crawlers.{}".format(self.prefix, self.nodename))
                                if sc >= 300 and sc <= 399:
                                    self.increment("{}.request.url.followers.crawlers.3xx.{}".format(self.prefix, self.nodename))
                                    self.gauges["{}.request.url.followers.crawlers.3xx.time-pct.{}.{}".format(self.prefix, "{}", self.nodename)].add(__d['Tt'])
                                    if __d['Tr'] > 0:
                                        self.gauges["{}.request.url.followers.crawlers.3xx.server-time-pct.{}.{}".format(self.prefix, "{}", self.nodename)].add(__d['Tr'])
                                else:
                                    if sc >= 400 and sc <= 499:
                                        self.increment("{}.request.url.followers.crawlers.4xx.{}".format(self.prefix, self.nodename))
                                    elif sc >= 500 and sc <= 599:
                                        self.increment("{}.request.url.followers.crawlers.5xx.{}".format(self.prefix, self.nodename))
                                    self.gauges["{}.request.url.followers.crawlers.time-pct.{}.{}".format(self.prefix, "{}", self.nodename)].add(__d['Tt'])
                                    if __d['Tr'] > 0:
                                        self.gauges["{}.request.url.followers.crawlers.server-time-pct.{}.{}".format(self.prefix, "{}", self.nodename)].add(__d['Tr'])
                        else:
                            if cc_event:
                                self.increment("{}.request.url.followers.non-crawlers.clientabort.status.{}.{}".format(self.prefix, status_code.lower(), self.nodename))
                            else:
                                self.increment("{}.request.url.followers.non-crawlers.{}".format(self.prefix, self.nodename))
                                if sc >= 300 and sc <= 399:
                                    self.increment("{}.request.url.followers.non-crawlers.3xx.{}".format(self.prefix, self.nodename))
                                    self.gauges["{}.request.url.followers.non-crawlers.3xx.time-pct.{}.{}".format(self.prefix, "{}", self.nodename)].add(__d['Tt'])
                                    if __d['Tr'] > 0:
                                        self.gauges["{}.request.url.followers.non-crawlers.3xx.server-time-pct.{}.{}".format(self.prefix, "{}", self.nodename)].add(__d['Tr'])
                                else:
                                    if sc >= 400 and sc <= 499:
                                        self.increment("{}.request.url.followers.non-crawlers.4xx.{}".format(self.prefix, self.nodename))
                                    elif sc >= 500 and sc <= 599:
                                        self.increment("{}.request.url.followers.non-crawlers.5xx.{}".format(self.prefix, self.nodename))
                                    self.gauges["{}.request.url.followers.non-crawlers.time-pct.{}.{}".format(self.prefix, "{}", self.nodename)].add(__d['Tt'])
                                    if __d['Tr'] > 0:
                                        self.gauges["{}.request.url.followers.non-crawlers.server-time-pct.{}.{}".format(self.prefix, "{}", self.nodename)].add(__d['Tr'])
                    elif ISSUUQUERY_PATTERN.match(__iu.path):
                        if is_spider:
                            if cc_event:
                                self.increment("{}.request.url.api-query.crawlers.clientabort.status.{}.{}".format(self.prefix, status_code.lower(), self.nodename))
                            else:
                                self.increment("{}.request.url.api-query.crawlers.{}".format(self.prefix, self.nodename))
                                if sc >= 300 and sc <= 399:
                                    self.increment("{}.request.url.api-query.crawlers.3xx.{}".format(self.prefix, self.nodename))
                                    self.gauges["{}.request.url.api-query.crawlers.3xx.time-pct.{}.{}".format(self.prefix, "{}", self.nodename)].add(__d['Tt'])
                                    if __d['Tr'] > 0:
                                        self.gauges["{}.request.url.api-query.crawlers.3xx.server-time-pct.{}.{}".format(self.prefix, "{}", self.nodename)].add(__d['Tr'])
                                else:
                                    if sc >= 400 and sc <= 499:
                                        self.increment("{}.request.url.api-query.crawlers.4xx.{}".format(self.prefix, self.nodename))
                                    elif sc >= 500 and sc <= 599:
                                        self.increment("{}.request.url.api-query.crawlers.5xx.{}".format(self.prefix, self.nodename))
                                    self.gauges["{}.request.url.api-query.crawlers.time-pct.{}.{}".format(self.prefix, "{}", self.nodename)].add(__d['Tt'])
                                    if __d['Tr'] > 0:
                                        self.gauges["{}.request.url.api-query.crawlers.server-time-pct.{}.{}".format(self.prefix, "{}", self.nodename)].add(__d['Tr'])
                        else:
                            if cc_event:
                                self.increment("{}.request.url.api-query.crawlers.clientabort.status.{}.{}".format(self.prefix, status_code.lower(), self.nodename))
                            else:
                                self.increment("{}.request.url.api-query.non-crawlers.{}".format(self.prefix, self.nodename))
                                if sc >= 300 and sc <= 399:
                                    self.increment("{}.request.url.api-query.non-crawlers.3xx.{}".format(self.prefix, self.nodename))
                                    self.gauges["{}.request.url.api-query.non-crawlers.3xx.time-pct.{}.{}".format(self.prefix, "{}", self.nodename)].add(__d['Tt'])
                                    if __d['Tr'] > 0:
                                        self.gauges["{}.request.url.api-query.non-crawlers.3xx.server-time-pct.{}.{}".format(self.prefix, "{}", self.nodename)].add(__d['Tr'])
                                else:
                                    if sc >= 400 and sc <= 499:
                                        self.increment("{}.request.url.api-query.non-crawlers.4xx.{}".format(self.prefix, self.nodename))
                                    elif sc >= 500 and sc <= 599:
                                        self.increment("{}.request.url.api-query.non-crawlers.5xx.{}".format(self.prefix, self.nodename))
                                    self.gauges["{}.request.url.api-query.non-crawlers.time-pct.{}.{}".format(self.prefix, "{}", self.nodename)].add(__d['Tt'])
                                    if __d['Tr'] > 0:
                                        self.gauges["{}.request.url.api-query.non-crawlers.server-time-pct.{}.{}".format(self.prefix, "{}", self.nodename)].add(__d['Tr'])
                    elif ISSUUSEARCH_PATTERN.match(__iu.path):
                        if is_spider:
                            if cc_event:
                                self.increment("{}.request.url.search.crawlers.clientabort.status.{}.{}".format(self.prefix, status_code.lower(), self.nodename))
                            else:
                                self.increment("{}.request.url.search.crawlers.{}".format(self.prefix, self.nodename))
                                if sc >= 300 and sc <= 399:
                                    self.increment("{}.request.url.search.crawlers.3xx.{}".format(self.prefix, self.nodename))
                                    self.gauges["{}.request.url.search.crawlers.3xx.time-pct.{}.{}".format(self.prefix, "{}", self.nodename)].add(__d['Tt'])
                                    if __d['Tr'] > 0:
                                        self.gauges["{}.request.url.search.crawlers.3xx.server-time-pct.{}.{}".format(self.prefix, "{}", self.nodename)].add(__d['Tr'])
                                else:
                                    if sc >= 400 and sc <= 499:
                                        self.increment("{}.request.url.search.crawlers.4xx.{}".format(self.prefix, self.nodename))
                                    elif sc >= 500 and sc <= 599:
                                        self.increment("{}.request.url.search.crawlers.5xx.{}".format(self.prefix, self.nodename))
                                    self.gauges["{}.request.url.search.crawlers.time-pct.{}.{}".format(self.prefix, "{}", self.nodename)].add(__d['Tt'])
                                    if __d['Tr'] > 0:
                                        self.gauges["{}.request.url.search.crawlers.server-time-pct.{}.{}".format(self.prefix, "{}", self.nodename)].add(__d['Tr'])
                        else:
                            if cc_event:
                                self.increment("{}.request.url.search.non-crawlers.clientabort.status.{}.{}".format(self.prefix, status_code.lower(), self.nodename))
                            else:
                                self.increment("{}.request.url.search.non-crawlers.{}".format(self.prefix, self.nodename))
                                if sc >= 300 and sc <= 399:
                                    self.increment("{}.request.url.search.non-crawlers.3xx.{}".format(self.prefix, self.nodename))
                                    self.gauges["{}.request.url.search.non-crawlers.3xx.time-pct.{}.{}".format(self.prefix, "{}", self.nodename)].add(__d['Tt'])
                                    if __d['Tr'] > 0:
                                        self.gauges["{}.request.url.search.non-crawlers.3xx.server-time-pct.{}.{}".format(self.prefix, "{}", self.nodename)].add(__d['Tr'])
                                else:
                                    if sc >= 400 and sc <= 499:
                                        self.increment("{}.request.url.search.non-crawlers.4xx.{}".format(self.prefix, self.nodename))
                                    elif sc >= 500 and sc <= 599:
                                        self.increment("{}.request.url.search.non-crawlers.5xx.{}".format(self.prefix, self.nodename))
                                    self.gauges["{}.request.url.search.non-crawlers.time-pct.{}.{}".format(self.prefix, "{}", self.nodename)].add(__d['Tt'])
                                    if __d['Tr'] > 0:
                                        self.gauges["{}.request.url.search.non-crawlers.server-time-pct.{}.{}".format(self.prefix, "{}", self.nodename)].add(__d['Tr'])
                    elif ISSUUPUBLISH_PATTERN.match(__iu.path):
                        if is_spider:
                            self.increment("{}.request.url.publish.crawlers.{}".format(self.prefix, self.nodename))
                            if sc >= 300 and sc <= 399:
                                self.increment("{}.request.url.publish.crawlers.3xx.{}".format(self.prefix, self.nodename))
                                self.gauges["{}.request.url.publish.crawlers.3xx.time-pct.{}.{}".format(self.prefix, "{}", self.nodename)].add(__d['Tt'])
                                if __d['Tr'] > 0:
                                    self.gauges["{}.request.url.publish.crawlers.3xx.server-time-pct.{}.{}".format(self.prefix, "{}", self.nodename)].add(__d['Tr'])
                            else:
                                if sc >= 400 and sc <= 499:
                                    self.increment("{}.request.url.publish.crawlers.4xx.{}".format(self.prefix, self.nodename))
                                elif sc >= 500 and sc <= 599:
                                    self.increment("{}.request.url.publish.crawlers.5xx.{}".format(self.prefix, self.nodename))
                                self.gauges["{}.request.url.publish.crawlers.time-pct.{}.{}".format(self.prefix, "{}", self.nodename)].add(__d['Tt'])
                                if __d['Tr'] > 0:
                                    self.gauges["{}.request.url.publish.crawlers.server-time-pct.{}.{}".format(self.prefix, "{}", self.nodename)].add(__d['Tr'])
                        else:
                            self.increment("{}.request.url.publish.non-crawlers.{}".format(self.prefix, self.nodename))
                            if sc >= 300 and sc <= 399:
                                self.increment("{}.request.url.publish.non-crawlers.3xx.{}".format(self.prefix, self.nodename))
                                self.gauges["{}.request.url.publish.non-crawlers.3xx.time-pct.{}.{}".format(self.prefix, "{}", self.nodename)].add(__d['Tt'])
                                if __d['Tr'] > 0:
                                    self.gauges["{}.request.url.publish.non-crawlers.3xx.server-time-pct.{}.{}".format(self.prefix, "{}", self.nodename)].add(__d['Tr'])
                            else:
                                if sc >= 400 and sc <= 499:
                                    self.increment("{}.request.url.publish.non-crawlers.4xx.{}".format(self.prefix, self.nodename))
                                elif sc >= 500 and sc <= 599:
                                    self.increment("{}.request.url.publish.non-crawlers.5xx.{}".format(self.prefix, self.nodename))
                                self.gauges["{}.request.url.publish.non-crawlers.time-pct.{}.{}".format(self.prefix, "{}", self.nodename)].add(__d['Tt'])
                                if __d['Tr'] > 0:
                                    self.gauges["{}.request.url.publish.non-crawlers.server-time-pct.{}.{}".format(self.prefix, "{}", self.nodename)].add(__d['Tr'])
                    elif ISSUUEXPLORE_PATTERN.match(__iu.path):
                        if is_spider:
                            self.increment("{}.request.url.explore.crawlers.{}".format(self.prefix, self.nodename))
                            if sc >= 300 and sc <= 399:
                                self.increment("{}.request.url.explore.crawlers.3xx.{}".format(self.prefix, self.nodename))
                                self.gauges["{}.request.url.explore.crawlers.3xx.time-pct.{}.{}".format(self.prefix, "{}", self.nodename)].add(__d['Tt'])
                                if __d['Tr'] > 0:
                                    self.gauges["{}.request.url.explore.crawlers.3xx.server-time-pct.{}.{}".format(self.prefix, "{}", self.nodename)].add(__d['Tr'])
                            else:
                                if sc >= 400 and sc <= 499:
                                    self.increment("{}.request.url.explore.crawlers.4xx.{}".format(self.prefix, self.nodename))
                                elif sc >= 500 and sc <= 599:
                                    self.increment("{}.request.url.explore.crawlers.5xx.{}".format(self.prefix, self.nodename))
                                self.gauges["{}.request.url.explore.crawlers.time-pct.{}.{}".format(self.prefix, "{}", self.nodename)].add(__d['Tt'])
                                if __d['Tr'] > 0:
                                    self.gauges["{}.request.url.explore.crawlers.server-time-pct.{}.{}".format(self.prefix, "{}", self.nodename)].add(__d['Tr'])
                        else:
                            self.increment("{}.request.url.explore.non-crawlers.{}".format(self.prefix, self.nodename))
                            if sc >= 300 and sc <= 399:
                                self.increment("{}.request.url.explore.non-crawlers.3xx.{}".format(self.prefix, self.nodename))
                                self.gauges["{}.request.url.explore.non-crawlers.3xx.time-pct.{}.{}".format(self.prefix, "{}", self.nodename)].add(__d['Tt'])
                                if __d['Tr'] > 0:
                                    self.gauges["{}.request.url.explore.non-crawlers.3xx.server-time-pct.{}.{}".format(self.prefix, "{}", self.nodename)].add(__d['Tr'])
                            else:
                                if sc >= 400 and sc <= 499:
                                    self.increment("{}.request.url.explore.non-crawlers.4xx.{}".format(self.prefix, self.nodename))
                                elif sc >= 500 and sc <= 599:
                                    self.increment("{}.request.url.explore.non-crawlers.5xx.{}".format(self.prefix, self.nodename))
                                self.gauges["{}.request.url.explore.non-crawlers.time-pct.{}.{}".format(self.prefix, "{}", self.nodename)].add(__d['Tt'])
                                if __d['Tr'] > 0:
                                    self.gauges["{}.request.url.explore.non-crawlers.server-time-pct.{}.{}".format(self.prefix, "{}", self.nodename)].add(__d['Tr'])
                    elif ISSUUMULTIPART_PATTERN.match(__iu.path):
                        if is_spider:
                            self.increment("{}.request.url.multipart.crawlers.{}".format(self.prefix, self.nodename))
                            if sc >= 300 and sc <= 399:
                                self.increment("{}.request.url.multipart.crawlers.3xx.{}".format(self.prefix, self.nodename))
                                self.gauges["{}.request.url.multipart.crawlers.3xx.time-pct.{}.{}".format(self.prefix, "{}", self.nodename)].add(__d['Tt'])
                                if __d['Tr'] > 0:
                                    self.gauges["{}.request.url.multipart.crawlers.3xx.server-time-pct.{}.{}".format(self.prefix, "{}", self.nodename)].add(__d['Tr'])
                            else:
                                if sc >= 400 and sc <= 499:
                                    self.increment("{}.request.url.multipart.crawlers.4xx.{}".format(self.prefix, self.nodename))
                                elif sc >= 500 and sc <= 599:
                                    self.increment("{}.request.url.multipart.crawlers.5xx.{}".format(self.prefix, self.nodename))
                                self.gauges["{}.request.url.multipart.crawlers.time-pct.{}.{}".format(self.prefix, "{}", self.nodename)].add(__d['Tt'])
                                if __d['Tr'] > 0:
                                    self.gauges["{}.request.url.multipart.crawlers.server-time-pct.{}.{}".format(self.prefix, "{}", self.nodename)].add(__d['Tr'])
                        else:
                            self.increment("{}.request.url.multipart.non-crawlers.{}".format(self.prefix, self.nodename))
                            if sc >= 300 and sc <= 399:
                                self.increment("{}.request.url.multipart.non-crawlers.3xx.{}".format(self.prefix, self.nodename))
                                self.gauges["{}.request.url.multipart.non-crawlers.3xx.time-pct.{}.{}".format(self.prefix, "{}", self.nodename)].add(__d['Tt'])
                                if __d['Tr'] > 0:
                                    self.gauges["{}.request.url.multipart.non-crawlers.3xx.server-time-pct.{}.{}".format(self.prefix, "{}", self.nodename)].add(__d['Tr'])
                            else:
                                if sc >= 400 and sc <= 499:
                                    self.increment("{}.request.url.multipart.non-crawlers.4xx.{}".format(self.prefix, self.nodename))
                                elif sc >= 500 and sc <= 599:
                                    self.increment("{}.request.url.multipart.non-crawlers.5xx.{}".format(self.prefix, self.nodename))
                                self.gauges["{}.request.url.multipart.non-crawlers.time-pct.{}.{}".format(self.prefix, "{}", self.nodename)].add(__d['Tt'])
                                if __d['Tr'] > 0:
                                    self.gauges["{}.request.url.multipart.non-crawlers.server-time-pct.{}.{}".format(self.prefix, "{}", self.nodename)].add(__d['Tr'])
                    elif ISSUUSIGNIN_PATTERN.match(__iu.path):
                        if is_spider:
                            self.increment("{}.request.url.signin.crawlers.{}".format(self.prefix, self.nodename))
                            if sc >= 300 and sc <= 399:
                                self.increment("{}.request.url.signin.crawlers.3xx.{}".format(self.prefix, self.nodename))
                                self.gauges["{}.request.url.signin.crawlers.3xx.time-pct.{}.{}".format(self.prefix, "{}", self.nodename)].add(__d['Tt'])
                                if __d['Tr'] > 0:
                                    self.gauges["{}.request.url.signin.crawlers.3xx.server-time-pct.{}.{}".format(self.prefix, "{}", self.nodename)].add(__d['Tr'])
                            else:
                                if sc >= 400 and sc <= 499:
                                    self.increment("{}.request.url.signin.crawlers.4xx.{}".format(self.prefix, self.nodename))
                                elif sc >= 500 and sc <= 599:
                                    self.increment("{}.request.url.signin.crawlers.5xx.{}".format(self.prefix, self.nodename))
                                self.gauges["{}.request.url.signin.crawlers.time-pct.{}.{}".format(self.prefix, "{}", self.nodename)].add(__d['Tt'])
                                if __d['Tr'] > 0:
                                    self.gauges["{}.request.url.signin.crawlers.server-time-pct.{}.{}".format(self.prefix, "{}", self.nodename)].add(__d['Tr'])
                        else:
                            self.increment("{}.request.url.signin.non-crawlers.{}".format(self.prefix, self.nodename))
                            if sc >= 300 and sc <= 399:
                                self.increment("{}.request.url.signin.non-crawlers.3xx.{}".format(self.prefix, self.nodename))
                                self.gauges["{}.request.url.signin.non-crawlers.3xx.time-pct.{}.{}".format(self.prefix, "{}", self.nodename)].add(__d['Tt'])
                                if __d['Tr'] > 0:
                                    self.gauges["{}.request.url.signin.non-crawlers.3xx.server-time-pct.{}.{}".format(self.prefix, "{}", self.nodename)].add(__d['Tr'])
                            else:
                                if sc >= 400 and sc <= 499:
                                    self.increment("{}.request.url.signin.non-crawlers.4xx.{}".format(self.prefix, self.nodename))
                                elif sc >= 500 and sc <= 599:
                                    self.increment("{}.request.url.signin.non-crawlers.5xx.{}".format(self.prefix, self.nodename))
                                self.gauges["{}.request.url.signin.non-crawlers.time-pct.{}.{}".format(self.prefix, "{}", self.nodename)].add(__d['Tt'])
                                if __d['Tr'] > 0:
                                    self.gauges["{}.request.url.signin.non-crawlers.server-time-pct.{}.{}".format(self.prefix, "{}", self.nodename)].add(__d['Tr'])
                    elif ISSUUSIGNUP_PATTERN.match(__iu.path):
                        if is_spider:
                            self.increment("{}.request.url.signup.crawlers.{}".format(self.prefix, self.nodename))
                            if sc >= 300 and sc <= 399:
                                self.increment("{}.request.url.signup.crawlers.3xx.{}".format(self.prefix, self.nodename))
                                self.gauges["{}.request.url.signup.crawlers.3xx.time-pct.{}.{}".format(self.prefix, "{}", self.nodename)].add(__d['Tt'])
                                if __d['Tr'] > 0:
                                    self.gauges["{}.request.url.signup.crawlers.3xx.server-time-pct.{}.{}".format(self.prefix, "{}", self.nodename)].add(__d['Tr'])
                            else:
                                if sc >= 400 and sc <= 499:
                                    self.increment("{}.request.url.signup.crawlers.4xx.{}".format(self.prefix, self.nodename))
                                elif sc >= 500 and sc <= 599:
                                    self.increment("{}.request.url.signup.crawlers.5xx.{}".format(self.prefix, self.nodename))
                                self.gauges["{}.request.url.signup.crawlers.time-pct.{}.{}".format(self.prefix, "{}", self.nodename)].add(__d['Tt'])
                                if __d['Tr'] > 0:
                                    self.gauges["{}.request.url.signup.crawlers.server-time-pct.{}.{}".format(self.prefix, "{}", self.nodename)].add(__d['Tr'])
                        else:
                            self.increment("{}.request.url.signup.non-crawlers.{}".format(self.prefix, self.nodename))
                            if sc >= 300 and sc <= 399:
                                self.increment("{}.request.url.signup.non-crawlers.3xx.{}".format(self.prefix, self.nodename))
                                self.gauges["{}.request.url.signup.non-crawlers.3xx.time-pct.{}.{}".format(self.prefix, "{}", self.nodename)].add(__d['Tt'])
                                if __d['Tr'] > 0:
                                    self.gauges["{}.request.url.signup.non-crawlers.3xx.server-time-pct.{}.{}".format(self.prefix, "{}", self.nodename)].add(__d['Tr'])
                            else:
                                if sc >= 400 and sc <= 499:
                                    self.increment("{}.request.url.signup.non-crawlers.4xx.{}".format(self.prefix, self.nodename))
                                elif sc >= 500 and sc <= 599:
                                    self.increment("{}.request.url.signup.non-crawlers.5xx.{}".format(self.prefix, self.nodename))
                                self.gauges["{}.request.url.signup.non-crawlers.time-pct.{}.{}".format(self.prefix, "{}", self.nodename)].add(__d['Tt'])
                                if __d['Tr'] > 0:
                                    self.gauges["{}.request.url.signup.non-crawlers.server-time-pct.{}.{}".format(self.prefix, "{}", self.nodename)].add(__d['Tr'])
                    elif ISSUUFBAPP_PATTERN.match(__iu.path):
                        if is_spider:
                            self.increment("{}.request.url.fbapp.crawlers.{}".format(self.prefix, self.nodename))
                            if sc >= 300 and sc <= 399:
                                self.increment("{}.request.url.fbapp.crawlers.3xx.{}".format(self.prefix, self.nodename))
                                self.gauges["{}.request.url.fbapp.crawlers.3xx.time-pct.{}.{}".format(self.prefix, "{}", self.nodename)].add(__d['Tt'])
                                if __d['Tr'] > 0:
                                    self.gauges["{}.request.url.fbapp.crawlers.3xx.server-time-pct.{}.{}".format(self.prefix, "{}", self.nodename)].add(__d['Tr'])
                            else:
                                if sc >= 400 and sc <= 499:
                                    self.increment("{}.request.url.fbapp.crawlers.4xx.{}".format(self.prefix, self.nodename))
                                elif sc >= 500 and sc <= 599:
                                    self.increment("{}.request.url.fbapp.crawlers.5xx.{}".format(self.prefix, self.nodename))
                                self.gauges["{}.request.url.fbapp.crawlers.time-pct.{}.{}".format(self.prefix, "{}", self.nodename)].add(__d['Tt'])
                                if __d['Tr'] > 0:
                                    self.gauges["{}.request.url.fbapp.crawlers.server-time-pct.{}.{}".format(self.prefix, "{}", self.nodename)].add(__d['Tr'])
                        else:
                            self.increment("{}.request.url.fbapp.non-crawlers.{}".format(self.prefix, self.nodename))
                            if sc >= 300 and sc <= 399:
                                self.increment("{}.request.url.fbapp.non-crawlers.3xx.{}".format(self.prefix, self.nodename))
                                self.gauges["{}.request.url.fbapp.non-crawlers.3xx.time-pct.{}.{}".format(self.prefix, "{}", self.nodename)].add(__d['Tt'])
                                if __d['Tr'] > 0:
                                    self.gauges["{}.request.url.fbapp.non-crawlers.3xx.server-time-pct.{}.{}".format(self.prefix, "{}", self.nodename)].add(__d['Tr'])
                            else:
                                if sc >= 400 and sc <= 499:
                                    self.increment("{}.request.url.fbapp.non-crawlers.4xx.{}".format(self.prefix, self.nodename))
                                elif sc >= 500 and sc <= 599:
                                    self.increment("{}.request.url.fbapp.non-crawlers.5xx.{}".format(self.prefix, self.nodename))
                                self.gauges["{}.request.url.fbapp.non-crawlers.time-pct.{}.{}".format(self.prefix, "{}", self.nodename)].add(__d['Tt'])
                                if __d['Tr'] > 0:
                                    self.gauges["{}.request.url.fbapp.non-crawlers.server-time-pct.{}.{}".format(self.prefix, "{}", self.nodename)].add(__d['Tr'])
                    elif __iu.path == "/":
                        if is_spider:
                            self.increment("{}.request.url.root.crawlers.{}".format(self.prefix, self.nodename))
                            if sc >= 300 and sc <= 399:
                                self.increment("{}.request.url.root.crawlers.3xx.{}".format(self.prefix, self.nodename))
                                self.gauges["{}.request.url.root.crawlers.3xx.time-pct.{}.{}".format(self.prefix, "{}", self.nodename)].add(__d['Tt'])
                                if __d['Tr'] > 0:
                                    self.gauges["{}.request.url.root.crawlers.3xx.server-time-pct.{}.{}".format(self.prefix, "{}", self.nodename)].add(__d['Tr'])
                            else:
                                if sc >= 400 and sc <= 499:
                                    self.increment("{}.request.url.root.crawlers.4xx.{}".format(self.prefix, self.nodename))
                                elif sc >= 500 and sc <= 599:
                                    self.increment("{}.request.url.root.crawlers.5xx.{}".format(self.prefix, self.nodename))
                                self.gauges["{}.request.url.root.crawlers.time-pct.{}.{}".format(self.prefix, "{}", self.nodename)].add(__d['Tt'])
                                if __d['Tr'] > 0:
                                    self.gauges["{}.request.url.root.crawlers.server-time-pct.{}.{}".format(self.prefix, "{}", self.nodename)].add(__d['Tr'])
                        else:
                            self.increment("{}.request.url.root.non-crawlers.{}".format(self.prefix, self.nodename))
                            if sc >= 300 and sc <= 399:
                                self.increment("{}.request.url.root.non-crawlers.3xx.{}".format(self.prefix, self.nodename))
                                self.gauges["{}.request.url.root.non-crawlers.3xx.time-pct.{}.{}".format(self.prefix, "{}", self.nodename)].add(__d['Tt'])
                                if __d['Tr'] > 0:
                                    self.gauges["{}.request.url.root.non-crawlers.3xx.server-time-pct.{}.{}".format(self.prefix, "{}", self.nodename)].add(__d['Tr'])
                            else:
                                if sc >= 400 and sc <= 499:
                                    self.increment("{}.request.url.root.non-crawlers.4xx.{}".format(self.prefix, self.nodename))
                                elif sc >= 500 and sc <= 599:
                                    self.increment("{}.request.url.root.non-crawlers.5xx.{}".format(self.prefix, self.nodename))
                                self.gauges["{}.request.url.root.non-crawlers.time-pct.{}.{}".format(self.prefix, "{}", self.nodename)].add(__d['Tt'])
                                if __d['Tr'] > 0:
                                    self.gauges["{}.request.url.root.non-crawlers.server-time-pct.{}.{}".format(self.prefix, "{}", self.nodename)].add(__d['Tr'])
                    else:
                        __im = ISSUUCALL_PATTERN.match(__iu.path)
                        if __im:
                            __ip = __im.groupdict()['subcall'].replace(".", "-")
                            if __ip:
                                if is_spider:
                                    self.increment("{}.request.url.api-call.crawlers.{}".format(self.prefix, self.nodename))
                                    self.gauges["{}.request.url.api-call.crawlers.time-pct.{}.{}".format(self.prefix, "{}", self.nodename)].add(__d['Tt'])
                                    if __d['Tr'] > 0:
                                        self.gauges["{}.request.url.api-call.crawlers.server-time-pct.{}.{}".format(self.prefix, "{}", self.nodename)].add(__d['Tr'])
                                    if sc >= 300 and sc <= 399:
                                        self.increment("{}.request.url.api-call.crawlers.3xx.{}".format(self.prefix, self.nodename))
                                        self.gauges["{}.request.url.api-call.crawlers.3xx.time-pct.{}.{}".format(self.prefix, "{}", self.nodename)].add(__d['Tt'])
                                        if __d['Tr'] > 0:
                                            self.gauges["{}.request.url.api-call.crawlers.3xx.server-time-pct.{}.{}".format(self.prefix, "{}", self.nodename)].add(__d['Tr'])
                                    else:
                                        if sc >= 400 and sc <= 499:
                                            self.increment("{}.request.url.api-call.crawlers.4xx.{}".format(self.prefix, self.nodename))
                                        elif sc >= 500 and sc <= 599:
                                            self.increment("{}.request.url.api-call.{}.crawlers.5xx.{}".format(self.prefix, __ip, self.nodename))
                                            self.increment("{}.request.url.api-call.crawlers.5xx.{}".format(self.prefix, self.nodename))
                                        if sc < 400 or sc > 499:
                                            self.increment("{}.request.url.api-call.{}.crawlers.{}".format(self.prefix, __ip, self.nodename))
                                            self.gauges["{}.request.url.api-call.{}.crawlers.time-pct.{}.{}".format(self.prefix, __ip, "{}", self.nodename)].add(__d['Tt'])
                                            if __d['Tr'] > 0:
                                                self.gauges["{}.request.url.api-call.{}.crawlers.server-time-pct.{}.{}".format(self.prefix, __ip, "{}", self.nodename)].add(__d['Tr'])
                                else:
                                    self.increment("{}.request.url.api-call.non-crawlers.{}".format(self.prefix, self.nodename))
                                    self.gauges["{}.request.url.api-call.non-crawlers.time-pct.{}.{}".format(self.prefix, "{}", self.nodename)].add(__d['Tt'])
                                    if __d['Tr'] > 0:
                                        self.gauges["{}.request.url.api-call.non-crawlers.server-time-pct.{}.{}".format(self.prefix, "{}", self.nodename)].add(__d['Tr'])
                                    if sc >= 300 and sc <= 399:
                                        self.increment("{}.request.url.api-call.non-crawlers.3xx.{}".format(self.prefix, self.nodename))
                                        self.gauges["{}.request.url.api-call.non-crawlers.3xx.time-pct.{}.{}".format(self.prefix, "{}", self.nodename)].add(__d['Tt'])
                                        if __d['Tr'] > 0:
                                            self.gauges["{}.request.url.api-call.non-crawlers.3xx.server-time-pct.{}.{}".format(self.prefix, "{}", self.nodename)].add(__d['Tr'])
                                    else:
                                        if sc >= 400 and sc <= 499:
                                            self.increment("{}.request.url.api-call.non-crawlers.4xx.{}".format(self.prefix, self.nodename))
                                        elif sc >= 500 and sc <= 599:
                                            self.increment("{}.request.url.api-call.{}.non-crawlers.5xx.{}".format(self.prefix, __ip, self.nodename))
                                            self.increment("{}.request.url.api-call.non-crawlers.5xx.{}".format(self.prefix, self.nodename))
                                        if sc < 400 or sc > 499:
                                            self.increment("{}.request.url.api-call.{}.non-crawlers.{}".format(self.prefix, __ip, self.nodename))
                                            self.gauges["{}.request.url.api-call.{}.non-crawlers.time-pct.{}.{}".format(self.prefix, __ip, "{}", self.nodename)].add(__d['Tt'])
                                            if __d['Tr'] > 0:
                                                self.gauges["{}.request.url.api-call.{}.non-crawlers.server-time-pct.{}.{}".format(self.prefix, __ip, "{}", self.nodename)].add(__d['Tr'])
                        else:
                            __im = ISSUUHOME_PATTERN.match(__iu.path)
                            if __im or __iu.path == "/home" or __iu.path == "/home/":
                                if __iu.path == "/home" or __iu.path == "/home/":
                                    __ip = "root"
                                else:
                                    __ip = __im.groupdict()['subhome'].replace(".", "-")
                                if __ip:
                                    if is_spider:
                                        self.increment("{}.request.url.home.crawlers.{}".format(self.prefix, self.nodename))
                                        self.gauges["{}.request.url.home.crawlers.time-pct.{}.{}".format(self.prefix, "{}", self.nodename)].add(__d['Tt'])
                                        if __d['Tr'] > 0:
                                            self.gauges["{}.request.url.home.crawlers.server-time-pct.{}.{}".format(self.prefix, "{}", self.nodename)].add(__d['Tr'])
                                        if sc >= 300 and sc <= 399:
                                            self.increment("{}.request.url.home.crawlers.3xx.{}".format(self.prefix, self.nodename))
                                            self.gauges["{}.request.url.home.crawlers.3xx.time-pct.{}.{}".format(self.prefix, "{}", self.nodename)].add(__d['Tt'])
                                            if __d['Tr'] > 0:
                                                self.gauges["{}.request.url.home.crawlers.3xx.server-time-pct.{}.{}".format(self.prefix, "{}", self.nodename)].add(__d['Tr'])
                                        else:
                                            if sc >= 400 and sc <= 499:
                                                self.increment("{}.request.url.home.crawlers.4xx.{}".format(self.prefix, self.nodename))
                                            elif sc >= 500 and sc <= 599:
                                                self.increment("{}.request.url.home.{}.crawlers.5xx.{}".format(self.prefix, __ip, self.nodename))
                                                self.increment("{}.request.url.home.crawlers.5xx.{}".format(self.prefix, self.nodename))
                                            if sc < 400 or sc > 499:
                                                self.increment("{}.request.url.home.{}.crawlers.{}".format(self.prefix, __ip, self.nodename))
                                                self.gauges["{}.request.url.home.{}.crawlers.time-pct.{}.{}".format(self.prefix, __ip, "{}", self.nodename)].add(__d['Tt'])
                                                if __d['Tr'] > 0:
                                                    self.gauges["{}.request.url.home.{}.crawlers.server-time-pct.{}.{}".format(self.prefix, __ip, "{}", self.nodename)].add(__d['Tr'])
                                    else:
                                        self.increment("{}.request.url.home.non-crawlers.{}".format(self.prefix, self.nodename))
                                        self.gauges["{}.request.url.home.non-crawlers.time-pct.{}.{}".format(self.prefix, "{}", self.nodename)].add(__d['Tt'])
                                        if __d['Tr'] > 0:
                                            self.gauges["{}.request.url.home.non-crawlers.server-time-pct.{}.{}".format(self.prefix, "{}", self.nodename)].add(__d['Tr'])
                                        if sc >= 300 and sc <= 399:
                                            self.increment("{}.request.url.home.non-crawlers.3xx.{}".format(self.prefix, self.nodename))
                                            self.gauges["{}.request.url.home.non-crawlers.3xx.time-pct.{}.{}".format(self.prefix, "{}", self.nodename)].add(__d['Tt'])
                                            if __d['Tr'] > 0:
                                                self.gauges["{}.request.url.home.non-crawlers.3xx.server-time-pct.{}.{}".format(self.prefix, "{}", self.nodename)].add(__d['Tr'])
                                        else:
                                            if sc >= 400 and sc <= 499:
                                                self.increment("{}.request.url.home.non-crawlers.4xx.{}".format(self.prefix, self.nodename))
                                            elif sc >= 500 and sc <= 599:
                                                self.increment("{}.request.url.home.{}.non-crawlers.5xx.{}".format(self.prefix, __ip, self.nodename))
                                                self.increment("{}.request.url.home.non-crawlers.5xx.{}".format(self.prefix, self.nodename))
                                            if sc < 400 or sc > 499:
                                                self.increment("{}.request.url.home.{}.non-crawlers.{}".format(self.prefix, __ip, self.nodename))
                                                self.gauges["{}.request.url.home.{}.non-crawlers.time-pct.{}.{}".format(self.prefix, __ip, "{}", self.nodename)].add(__d['Tt'])
                                                if __d['Tr'] > 0:
                                                    self.gauges["{}.request.url.home.{}.non-crawlers.server-time-pct.{}.{}".format(self.prefix, __ip, "{}", self.nodename)].add(__d['Tr'])
                            else:
                                __im = ISSUUPIXEL_PATTERN.match(__iu.path)
                                if __im or __iu.path == "/v1" or __iu.path == "/v1/":
                                    if __iu.path == "/v1" or __iu.path == "/v1/":
                                        __ip = "root"
                                    else:
                                        __ip = __im.groupdict()['pixel'].replace(".", "-")
                                    if __ip:
                                        if is_spider:
                                            self.increment("{}.request.url.pixeltrack.crawlers.{}".format(self.prefix, self.nodename))
                                            self.gauges["{}.request.url.pixeltrack.crawlers.time-pct.{}.{}".format(self.prefix, "{}", self.nodename)].add(__d['Tt'])
                                            if __d['Tr'] > 0:
                                                self.gauges["{}.request.url.pixeltrack.crawlers.server-time-pct.{}.{}".format(self.prefix, "{}", self.nodename)].add(__d['Tr'])
                                            if sc >= 300 and sc <= 399:
                                                self.increment("{}.request.url.pixeltrack.crawlers.3xx.{}".format(self.prefix, self.nodename))
                                                self.gauges["{}.request.url.pixeltrack.crawlers.3xx.time-pct.{}.{}".format(self.prefix, "{}", self.nodename)].add(__d['Tt'])
                                                if __d['Tr'] > 0:
                                                    self.gauges["{}.request.url.pixeltrack.crawlers.3xx.server-time-pct.{}.{}".format(self.prefix, "{}", self.nodename)].add(__d['Tr'])
                                            else:
                                                if sc >= 400 and sc <= 499:
                                                    self.increment("{}.request.url.pixeltrack.crawlers.4xx.{}".format(self.prefix, self.nodename))
                                                elif sc >= 500 and sc <= 599:
                                                    self.increment("{}.request.url.pixeltrack.{}.crawlers.5xx.{}".format(self.prefix, __ip, self.nodename))
                                                    self.increment("{}.request.url.pixeltrack.crawlers.5xx.{}".format(self.prefix, self.nodename))
                                                if sc < 400 or sc > 499:
                                                    self.increment("{}.request.url.pixeltrack.{}.crawlers.{}".format(self.prefix, __ip, self.nodename))
                                                    self.gauges["{}.request.url.pixeltrack.{}.crawlers.time-pct.{}.{}".format(self.prefix, __ip, "{}", self.nodename)].add(__d['Tt'])
                                                    if __d['Tr'] > 0:
                                                        self.gauges["{}.request.url.pixeltrack.{}.crawlers.server-time-pct.{}.{}".format(self.prefix, __ip, "{}", self.nodename)].add(__d['Tr'])
                                        else:
                                            self.increment("{}.request.url.pixeltrack.non-crawlers.{}".format(self.prefix, self.nodename))
                                            self.gauges["{}.request.url.pixeltrack.non-crawlers.time-pct.{}.{}".format(self.prefix, "{}", self.nodename)].add(__d['Tt'])
                                            if __d['Tr'] > 0:
                                                self.gauges["{}.request.url.pixeltrack.non-crawlers.server-time-pct.{}.{}".format(self.prefix, "{}", self.nodename)].add(__d['Tr'])
                                            if sc >= 300 and sc <= 399:
                                                self.increment("{}.request.url.pixeltrack.non-crawlers.3xx.{}".format(self.prefix, self.nodename))
                                                self.gauges["{}.request.url.pixeltrack.non-crawlers.3xx.time-pct.{}.{}".format(self.prefix, "{}", self.nodename)].add(__d['Tt'])
                                                if __d['Tr'] > 0:
                                                    self.gauges["{}.request.url.pixeltrack.non-crawlers.3xx.server-time-pct.{}.{}".format(self.prefix, "{}", self.nodename)].add(__d['Tr'])
                                            else:
                                                if sc >= 400 and sc <= 499:
                                                    self.increment("{}.request.url.pixeltrack.non-crawlers.4xx.{}".format(self.prefix, self.nodename))
                                                elif sc >= 500 and sc <= 599:
                                                    self.increment("{}.request.url.pixeltrack.{}.non-crawlers.5xx.{}".format(self.prefix, __ip, self.nodename))
                                                    self.increment("{}.request.url.pixeltrack.non-crawlers.5xx.{}".format(self.prefix, self.nodename))
                                                if sc < 400 or sc > 499:
                                                    self.increment("{}.request.url.pixeltrack.{}.non-crawlers.{}".format(self.prefix, __ip, self.nodename))
                                                    self.gauges["{}.request.url.pixeltrack.{}.non-crawlers.time-pct.{}.{}".format(self.prefix, __ip, "{}", self.nodename)].add(__d['Tt'])
                                                    if __d['Tr'] > 0:
                                                        self.gauges["{}.request.url.pixeltrack.{}.non-crawlers.server-time-pct.{}.{}".format(self.prefix, __ip, "{}", self.nodename)].add(__d['Tr'])
                except:
                    pass

            for backend in ["backend-" + __d['backend_name'], "all-backends"]:
                suffix = "{}.{}".format(self.nodename, backend.replace(".", "-"))

                if cc_event:
                    self.increment("{}.response.clientabort.status.{}.{}".format(self.prefix, status_code.lower(), suffix))
                else:
                    self.increment("{}.response.status.{}.{}".format(self.prefix, status_code.lower(), suffix))
                self.increment("{}.request.method.{}.{}".format(self.prefix, method.lower(), suffix))

                self.gauges["{}.bytesread-pct.{}.{}".format(self.prefix, "{}", suffix)].add(__d['bytes_read'])
                self.gauges["{}.request-time-pct.{}.{}".format(self.prefix, "{}", suffix)].add(__d['Tt'])
                if __d['Tr'] > 0:
                    self.gauges["{}.server-time-pct.{}.{}".format(self.prefix, "{}", suffix)].add(__d['Tr'])

        else:
            __m = self.updown_pattern.match(line)
            if __m:
                __d = __m.groupdict()
                for backend in ["backend-" + __d['backend_name'], "all-backends"]:
                    suffix = "{}.{}".format(self.nodename, backend.replace(".", "-"))
                    if __d['updown'] == 'DOWN' or __d['updown'] == 'UP':
                        self.increment("{}.meta.up-down.{}".format(self.prefix, suffix))
                    else:
                        print >> sys.stderr, 'Failed to parse line: %s' % line
                        self.increment("{}.meta.unparsed-lines.{}".format(self.prefix, self.nodename))
            else:
                __m = self.startstop_pattern.match(line)
                if __m:
                    __d = __m.groupdict()
                    self.counters["{}.meta.start-stop.{}".format(self.prefix, self.nodename)] = 1
                else:
                    __m = self.noserver_pattern.match(line)
                    if __m:
                        #__d = __m.groupdict()
                        self.counters["{}.meta.noserver.{}".format(self.prefix, self.nodename)] = 1
                    else:
                        #raise LogsterParsingException, "Failed to parse line: %s" % line
                        print >> sys.stderr, 'Failed to parse line: %s' % line
                        self.increment("{}.meta.unparsed-lines.{}".format(self.prefix, self.nodename))

    def increment(self, name):
        '''increment'''
        self.counters[name] += 1

    def get_state(self, duration):
        '''get_state'''
        metrics = []

        for backend in self.ip_counter:
            suffix = "{}.{}".format(self.nodename, backend.replace(".", "-"))
            variance = 0
            try:
                ips = self.ip_counter[backend]
                if len(ips) > 0:
                    sample = ips.values()
                    if len(sample) > 0:
                        variance = reduce(lambda x,y: x+y, map(lambda xi: (xi-(float(reduce(lambda x,y : x+y, sample)) / len(sample)))**2, sample))/ len(sample)
            except:
                pass
            self.counters["{}.stats.backend.ip-variance.{}".format(self.prefix, suffix)] = int(variance)

        for name, value in self.counters.items():
            metrics.append(MetricObject(name, value))

        for name, value in self.gauges.items():
            metrics.extend(value.as_metrics(name))

        return metrics
