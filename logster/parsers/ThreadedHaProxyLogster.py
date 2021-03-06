'''
A logster parser for haproxy log files in the HTTP format.
Reports percentiles for processing time and data sizes.
Accumulates by host and across backends.
'''

import threading
import os
import sys
import re
import math
import optparse
import cPickle as pickle
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
STATUS_CODES = [200,204,206,301,302,304,307,308,400,401,403,404,405,408,410,416,451,500,502,503,504]

# Most common
LANGUAGES = ['en','es','pt','zh','ja','de','it','fr','ru','da','ar']

LINUX_VARIANTS = ['Linux', 'Ubuntu', 'Debian', 'Fedora', 'Gentoo', 'Red Hat', 'SUSE']

# In case we cannot detect the User-Agent use this crud detection of crawlers
BOT_PATTERN = re.compile('.*(Googlebot[/-]| Ezooms/|WinHttp\.WinHttpRequest|heritrix/|Java/|[Pp]ython|Siteimprove.com|Catchpoint|Exabot|Crawler|Bot|Spider|AndroidDownloadManager|URL2File/|[Ss]entry/|Apache-HttpClient/|PHP[/ ]|Wget/|Mediapartners-Google|AdsBot-Google|curl/|WordPress/|Twitter/|archiver|check_http/|node-fetch/|Nutch/|ColdFusion|WhatsApp/|Clickagy|GetIntent|Twitter|<\?php |(http://|\w+@)\w+(\.\w+)+)')
IMGPROXY_PATTERN = re.compile('.*\(via ggpht.com GoogleImageProxy\)')
PREVIEW_PATTERN = re.compile('.*Google Web Preview\)')

# /<account>/docs/<document>
ISSUUDOC_PATTERN = re.compile('^/[^/]+/docs($|/.+)')
ISSUUSTACKS_PATTERN = re.compile('^/[^/]+/stacks($|/.+)')
ISSUUFOLLOWERS_PATTERN = re.compile('^/[^/]+/followers($|/.+)')
ISSUUCALL_PATTERN = re.compile('^(/|/api/)(internal_call|call|res)/(?P<subcall>[^/]+)/.+')
ISSUUHOME_PATTERN = re.compile('^/home/(?P<subhome>[^/]+)')
ISSUUQUERY_PATTERN = re.compile('^(/|/api/)query($|/.+)')
ISSUUSEARCH_PATTERN = re.compile('^/search($|/.+)')
ISSUUPUBLISH_PATTERN = re.compile('^/publish($|/.+)')
ISSUUEXPLORE_PATTERN = re.compile('^/explore($|/.+)')
ISSUUPRICING_PATTERN = re.compile('^/pricing($|/.+)')
ISSUUMULTIPART_PATTERN = re.compile('^/multipart($|/.+)')
ISSUUSIGNIN_PATTERN = re.compile('^/signin($|/.+)')
ISSUUSIGNUP_PATTERN = re.compile('^/signup($|/.+)')
ISSUUFBAPP_PATTERN = re.compile('^/_fbapp($|/.+)')
ISSUUPIXEL_PATTERN = re.compile('^/v1/(?P<pixel>[^?]*)')
ISSUUEMAILREJECTED_PATTERN = re.compile('^/emailrejected($|/.+)')
ISSUUOPTOUT_PATTERN = re.compile('^/optout($|/.+)')
ISSUUOEMBED_PATTERN = re.compile('^/(oembed|oembed_wp|oembed_tumblr)($|/.+)')
ISSUUPUBLISHERSTORE_PATTERN = re.compile('^/store/publishers/(?P<publisher>[^/]+)/docs/.+')
ISSUUCLAIM_PATTERN = re.compile('^/claim-account($|/.+)')

ISSUU_THINLAYER_CALLS = [
    '_debug',
    'ads',
    'articles',
    'backend-category',
    'backend-iab-category',
    'backend-search-suggestions',
    'billing',
    'clippings',
    'clippingsv2',
    'community',
    'documentpage',
    'document-page',
    'fbpagetab',
    'history',
    'hmm',
    'inpubad',
    'inspect',
    'inspection',
    'interests',
    'internal_call',
    'licensing',
    'mobile',
    'notifier',
    'partner',
    'payment',
    'paywall',
    'print-on-demand',
    'profile-backend',
    'promoted',
    'protecteddocument',
    'protectedimage',
    'protectedpage',
    'publisher-suite',
    'reader',
    'reader3',
    'recommendations',
    'stream'
]

ISSUU_HOME_CALLS = [
    '_debug',
    'campaigns',
    'collaborate',
    'docs',
    'fbapp',
    'following',
    'activity',
    'publications',
    'publisher',
    'purchases',
    'sell',
    'services',
    'settings',
    'statistics'
]

magma_patterns = [
  {'pattern':  re.compile('^/about($|/.+)'), 'metric': 'about' },

  {'pattern':  re.compile('^/admins/dashboard($|/.+)'), 'metric': 'admins-dashboard' },
  {'pattern':  re.compile('^/admins/sign_in($|/.+)'), 'metric': 'admins-signin' },
  {'pattern':  re.compile('^/admins/sign_out($|/.+)'), 'metric': 'admins-signout' },
  {'pattern':  re.compile('^/admins/users($|/$)'), 'metric': 'admins-users' },
  {'pattern':  re.compile('^/admins/users/collaborators($|/.+)'), 'metric': 'admins-users-collaborators' },
  {'pattern':  re.compile('^/admins/users/freebies($|/.+)'), 'metric': 'admins-users-freebies' },
  {'pattern':  re.compile('^/admins/users/licensed($|/.+)'), 'metric': 'admins-users-licensed' },
  {'pattern':  re.compile('^/admins/users/locked($|/.+)'), 'metric': 'admins-users-locked' },
  {'pattern':  re.compile('^/admins/users/new($|/.+)'), 'metric': 'admins-users-new' },
  {'pattern':  re.compile('^/admins/users/not_migrated($|/.+)'), 'metric': 'admins-users-notmigrated' },
  {'pattern':  re.compile('^/admins/users/search($|/.+)'), 'metric': 'admins-users-search' },
  {'pattern':  re.compile('^/admins/users/[^/]+/add_credit($|/.+)'), 'metric': 'admins-users-addcredit' },
  {'pattern':  re.compile('^/admins/users/[^/]+/become($|/.+)'), 'metric': 'admins-users-become' },
  {'pattern':  re.compile('^/admins/users/[^/]+/edit($|/.+)'), 'metric': 'admins-users-edit' },
  {'pattern':  re.compile('^/admins/users/[^/]+/remove_credit($|/.+)'), 'metric': 'admins-users-removecredit' },

  {'pattern':  re.compile('^/api/authentications$'), 'metric': 'api-authentications' },
  {'pattern':  re.compile('^/api/authentications/new($|/.+)'), 'metric': 'api-authentications-new' },
  {'pattern':  re.compile('^/api/crash_reports$'), 'metric': 'api-crashreports' },
  {'pattern':  re.compile('^/api/issues$'), 'metric': 'api-issues' },
  {'pattern':  re.compile('^/api/issues/[^/]+/editors($|/.+)'), 'metric': 'api-issues-editors' },
  {'pattern':  re.compile('^/api/issues/[^/]+/notification($|/.+)'), 'metric': 'api-issues-notification' },
  {'pattern':  re.compile('^/api/issues/[^/]+/articles($|/.+)'), 'metric': 'api-issues-articles' },
  {'pattern':  re.compile('^/api/issues/[^/]+/pages\.xml($|\?.+)'), 'metric': 'api-issues-pagesxml' },
  {'pattern':  re.compile('^/api/issues/[^/]+/pages/[^/]*$'), 'metric': 'api-issues-pages' },
  {'pattern':  re.compile('^/api/issues/[^/]+/pages/[^/]+/content($|/.+)'), 'metric': 'api-issues-pages-content' },
  {'pattern':  re.compile('^/api/issues\.xml($|\?.+)'), 'metric': 'api-issuesxml' },
  {'pattern':  re.compile('^/api/s3_certificate($|\?.+)'), 'metric': 'api-s3certificate' },
  {'pattern':  re.compile('^/api_issuu/call/licensing($|/.+)'), 'metric': 'api-issuu-licensing' },
  {'pattern':  re.compile('^/api_issuu/query($|/.+)'), 'metric': 'api-issuu-query' },

  {'pattern':  re.compile('^/assets($|/.+)'), 'metric': 'assets' },

  {'pattern':  re.compile('^/delayed_job_admin($|/.+)'), 'metric': 'delayed-jobadmin' },

  {'pattern':  re.compile('^/invitations/[^/]+/accept_with_existing_user($|/.+)'), 'metric': 'invitations-acceptwithexistinguser' },
  {'pattern':  re.compile('^/invitations/[^/]+/accept_with_new_user($|/.+)'), 'metric': 'invitations-acceptwithnewuser' },

  {'pattern':  re.compile('^/magmin($|/.+)'), 'metric': 'magmin' },
  {'pattern':  re.compile('^/navigation_panel($|/.+)'), 'metric': 'navigationpanel' },
  {'pattern':  re.compile('^/customers($|/.+)'), 'metric': 'customers' },
  {'pattern':  re.compile('^/hidden_tips($|/.+)'), 'metric': 'hidden_tips' },
  {'pattern':  re.compile('^/mobile($|/.+)'), 'metric': 'mobile' },
  {'pattern':  re.compile('^/pricing($|/.+)'), 'metric': 'pricing' },
  {'pattern':  re.compile('^/tour($|/.+)'), 'metric': 'tour' },

  {'pattern':  re.compile('^/publications/[^/]+/articles/[^/]+/assets($|/.+)'), 'metric': 'publications-articles-assets' },
  {'pattern':  re.compile('^/publications/[^/]+/articles/[^/]+/comparison\.js($|/.+)'), 'metric': 'publications-articles-comparisonjs' },
  {'pattern':  re.compile('^/publications/[^/]+/articles/[^/]+/comparison($|/.+)'), 'metric': 'publications-articles-comparison' },
  {'pattern':  re.compile('^/publications/[^/]+/articles/[^/]+/do_assign($|/.+)'), 'metric': 'publications-articles-doassign' },
  {'pattern':  re.compile('^/publications/[^/]+/articles/[^/]+/new_assign($|/.+)'), 'metric': 'publications-articles-newassign' },
  {'pattern':  re.compile('^/publications/[^/]+/dashboard($|/.+)'), 'metric': 'publications-dashboard' },
  {'pattern':  re.compile('^/publications/[^/]+/issues/[^/]+/advertisements($|/.+)'), 'metric': 'publications-issues-advertisements' },
  {'pattern':  re.compile('^/publications/[^/]+/issues/[^/]+/articles($|/.+)'), 'metric': 'publications-issues-articles' },
  {'pattern':  re.compile('^/publications/[^/]+/issues/[^/]+/content_bundles($|/.+)'), 'metric': 'publications-issues-contentbundles' },
  {'pattern':  re.compile('^/publications/[^/]+/issues/[^/]+/flatplan($|/.+)'), 'metric': 'publications-issues-flatplan' },
  {'pattern':  re.compile('^/publications/[^/]+/issues/[^/]+/layout($|/.+)'), 'metric': 'publications-issues-layout' },
  {'pattern':  re.compile('^/publications/[^/]+/issues/[^/]+/pages($|/.+)'), 'metric': 'publications-issues-pages' },
  {'pattern':  re.compile('^/publications/[^/]+/issues/[^/]+/publish($|/.+)'), 'metric': 'publications-issues-publish' },
  {'pattern':  re.compile('^/publications/[^/]+/issues/[^/]+/reviews($|/.+)'), 'metric': 'publications-issues-reviews' },
  {'pattern':  re.compile('^/publications/[^/]+/issues/[^/]+/spreads($|/.+)'), 'metric': 'publications-issues-spreads' },
  {'pattern':  re.compile('^/publications/[^/]+/issues($|\?.+)'), 'metric': 'publications-issues' },
  {'pattern':  re.compile('^/publications/[^/]+/notifications($|\?.+)'), 'metric': 'publications-notifications' },
  {'pattern':  re.compile('^/publications/[^/]+/permissions($|/.+)'), 'metric': 'publications-permissions' },
  {'pattern':  re.compile('^/publications/[^/]+/team($|/.+)'), 'metric': 'publications-team' },

  {'pattern':  re.compile('^/system_notifications($|/.+)'), 'metric': 'system-notifications' },

  {'pattern':  re.compile('^/users/account($|/.+)'), 'metric': 'users-account' },
  {'pattern':  re.compile('^/users/edit($|/.+)'), 'metric': 'users-edit' },
  {'pattern':  re.compile('^/users/migration/existing_account($|/.+)'), 'metric': 'users-migration-existingaccount' },
  {'pattern':  re.compile('^/users/migration/new_account($|/.+)'), 'metric': 'users-migration-newaccount' },
  {'pattern':  re.compile('^/users/migration($|/.+)'), 'metric': 'users-migration' },
  {'pattern':  re.compile('^/users/password/new($|/.+)'), 'metric': 'users-password-new' },
  {'pattern':  re.compile('^/users/sign_in($|/.+)'), 'metric': 'users-signin' },
  {'pattern':  re.compile('^/users/sign_out($|/.+)'), 'metric': 'users-signout' },
  {'pattern':  re.compile('^/users($|/.+)'), 'metric': 'users' }
]

# haproxy.<host>.<backend>.request.method
# haproxy.<host>.<backend>.response.code.<status>
#

from logster.logster_helper import MetricObject, LogsterParser
from logster.logster_helper import LogsterParsingException

from socket import socket, gethostbyname, gethostbyaddr, AF_UNIX, SOCK_STREAM

HaP_OK = 1
HaP_ERR = 2
HaP_SOCK_ERR = 3
HaP_BUFSIZE = 8192

threads = []
lock = threading.Lock()

# an associative array. In python these are called dictionaries.
# load cache
try:
    ua_cache = pickle.load( open( "/var/tmp/haproxy_logster_ua.p", "rb" ) )
except:
    ua_cache = {}
try:
    ip_cache = pickle.load( open( "/var/tmp/haproxy_logster_ip.p", "rb" ) )
except:
    ip_cache = {}
try:
    googlebot_cache = pickle.load( open( "/var/tmp/haproxy_logster_googlebot.p", "rb" ) )
except:
    googlebot_cache = {}
try:
    bingbot_cache = pickle.load( open( "/var/tmp/haproxy_logster_bingbot.p", "rb" ) )
except:
    bingbot_cache = {}

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


ip_counter = {}
url_counter = {}
log_def = []
regexs = []
headers = None
status_codes = defaultdict(lambda: defaultdict(lambda: 0))
methods = defaultdict(lambda: defaultdict(lambda: 0))
response_time = defaultdict(PercentileMetric)
prefix = PREFIX
nodename = NODENAME.replace(".", "-")

counters = defaultdict(lambda: 0)
gauges = defaultdict(PercentileMetric)

issuu = False
magma = False
usexffip = False
verifybot = []

GOOGLERDNS_PATTERN = re.compile('.*\.googlebot\.com$')
def verifyGoogleBot(ip):
    # ip.ip is an integer repr of the ip
    _isTrueBot = googlebot_cache.get(ip.ip)
    if _isTrueBot is None:
        try:
            _n = gethostbyaddr(ip.strNormal())[0]
            _isTrueBot = GOOGLERDNS_PATTERN.match(_n) is not None and gethostbyname(_n) == ip.strNormal()
        except:
            _isTrueBot = False
        googlebot_cache[ip.ip] = _isTrueBot
    return _isTrueBot


BINGRDNS_PATTERN = re.compile('.*\.search\.msn\.com$')
def verifyBingBot(ip):
    # ip.ip is an integer repr of the ip
    _isTrueBot = bingbot_cache.get(ip.ip)
    if _isTrueBot is None:
        try:
            _n = gethostbyaddr(ip.strNormal())[0]
            _isTrueBot = BINGRDNS_PATTERN.match(_n) is not None and gethostbyname(_n) == ip.strNormal()
        except:
            _isTrueBot = False
        bingbot_cache[ip.ip] = _isTrueBot
    return _isTrueBot

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

global patterns
global log_line_pattern
global updown_pattern
global health_pattern
global startstop_pattern
global noserver_pattern

def build_pattern():
    '''build_pattern'''
    global patterns
    __rx = None
    __p = ""
    for i in patterns:
        __p = __p + i
        try:
            __rx = re.compile(__p)
        except Exception as e:
            #raise LogsterParsingException, "pattern compile failure: %s" % e
            print >> sys.stderr, "pattern compile failure: %s" % e
            sys.exit(2)
    return __rx

def add_pattern(name, pattern, spacer=" ", leader=""):
    '''add_pattern'''
    global patterns
    patterns.append(r'{}(?P<{}>{}){}'.format(leader, name, pattern, spacer))
    log_def.append(name)

def reset_pattern():
    global patterns
    '''reset_pattern'''
    patterns = []

def extract_method(request):
    '''extract_method'''
    if request == '<BADREQ>':
        return 'BADREQ'
    elif request.upper() in REQUEST_METHODS:
        return request
    else:
        return 'OTHER'

def extract_status_code(status_code):
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

def add_gauge(lock, name, value):
    lock.acquire()
    gauges[name].add(value)
    lock.release()

def global_increment(lock, name):
    '''increment'''
    lock.acquire()
    counters[name] += 1
    lock.release()

def global_urlstat(lock, sc, status_code, cc_event, cd_event, is_spider, r, metric_key):
    metric_ua = "crawlers" if is_spider else "non-crawlers"

    # if this is dynamic key and this is the first time we "see" it zero out all relevant statuc codes.
    _kp = "{}.request.url.{}.{}".format(prefix, metric_key, metric_ua)
    _k  = "{}.{}".format(_kp, nodename)
    lock.acquire()
    if not _k in counters:
        counters[_k] = 0
        counters["{}.3xx.{}".format(_kp, nodename)] = 0
        counters["{}.4xx.{}".format(_kp, nodename)] = 0
        counters["{}.5xx.{}".format(_kp, nodename)] = 0
        for _sc in [301,302,304]:
            counters["{}.3xx.{}.{}".format(_kp, _sc, nodename)] = 0
        for _sc in [400,401,403,404]:
            counters["{}.4xx.{}.{}".format(_kp, _sc, nodename)] = 0
        for _sc in [500,502,503,504]:
            counters["{}.5xx.{}.{}".format(_kp, _sc, nodename)] = 0
    lock.release()

    if cc_event:
        global_increment(lock,"{}.clientabort.status.{}.{}".format(_kp, status_code.lower(), nodename))
    elif cd_event:
        global_increment(lock,"{}.clientdisconnect.status.{}.{}".format(_kp, status_code.lower(), nodename))
    else:
        global_increment(lock,_k)
        if sc >= 300 and sc <= 399:
            global_increment(lock,"{}.3xx.{}".format(_kp, nodename))
            if sc in [301,302,304]:
                global_increment(lock,"{}.3xx.{}.{}".format(_kp, sc, nodename))
            add_gauge(lock,"{}.3xx.time-pct.{}.{}".format(_kp, "{}", nodename),r['Tt'])
            if r['Tr'] > 0:
                add_gauge(lock,"{}.3xx.server-time-pct.{}.{}".format(_kp, "{}", nodename),r['Tr'])
        else:
            if sc >= 400 and sc <= 499:
                global_increment(lock,"{}.4xx.{}".format(_kp, nodename))
                if sc in [400,401,403,404]:
                    global_increment(lock,"{}.4xx.{}.{}".format(_kp, sc, nodename))
            elif sc >= 500 and sc <= 599:
                global_increment(lock,"{}.5xx.{}".format(_kp, nodename))
                if sc in [500,502,503,504]:
                    global_increment(lock,"{}.5xx.{}.{}".format(_kp, sc, nodename))
            add_gauge(lock,"{}.time-pct.{}.{}".format(_kp, "{}", nodename),r['Tt'])
            if r['Tr'] > 0:
                add_gauge(lock,"{}.server-time-pct.{}.{}".format(_kp, "{}", nodename),r['Tr'])

def threaded_parse_line(lock,line):
    '''parse_line'''

    method = ''
    status_code = ''
    sc = -1

    tarpit = False
    block  = False

    # Detect/Handle Spiders/Crawlers
    is_spider = False
    is_img_proxy = False
    is_preview_browser = False

    # clientabort
    # CC   The client aborted before the connection could be established to the
    #      server. This can happen when haproxy tries to connect to a recently
    #      dead (or unchecked) server, and the client aborts while haproxy is
    #      waiting for the server to respond or for "timeout connect" to expire.
    cc_event = False

    # clientdisconnect
    # CD   The client unexpectedly aborted during data transfer. This can be
    #      caused by a browser crash, by an intermediate equipment between the
    #      client and haproxy which decided to actively break the connection,
    #      by network routing issues between the client and haproxy, or by a
    #      keep-alive session between the server and the client terminated first
    #      by the client.
    cd_event = False

    def increment(name):
        global_increment(lock, name)

    def urlstat(r, metric_key):
        global_urlstat(lock, sc, status_code, cc_event, cd_event, is_spider, r, metric_key)

    __m = log_line_pattern.match(line)
    if __m:
        __d = __m.groupdict()

        method      = extract_method(__d['method'])
        status_code = extract_status_code(__d['status_code'])
        tarpit      = __d['term_event']=='P' and __d['term_session']=='T'
        block       = __d['term_event']=='P' and __d['term_session']=='R'
        # annoying chinese sites causing 503s because of client aborts
        cc_event    = __d['term_event']=='C' and __d['term_session']=='C'
        cd_event    = __d['term_event']=='C' and __d['term_session']=='D'

        if tarpit:
            # Do not process any further iff tarpit
            increment("{}.request.tarpit.{}".format(prefix, nodename))
            return

        if block:
            # Do not process any further iff block
            increment("{}.request.block.{}".format(prefix, nodename))
            return

        try:
            sc = int(status_code)
        except:
            sc = -1

        ua  = None
        al  = None
        dnt = None
        xff = None
        if headers and __d['captured_request_headers']:
            crhs = __d['captured_request_headers'].split('|')
            if len(crhs) == len(headers):
                for i in range(len(crhs)):
                    __d['crh_'+headers[i]] = crhs[i]

                _uastr = __d.get('crh_user-agent')
                if _uastr is not None:
                    normalized_ua = _uastr.replace('User-Agent: ','',1)
                    ua = ua_cache.get(normalized_ua)
                    if ua is None:
                        ua = user_agent_parser.Parse(normalized_ua)
                        ua_cache[normalized_ua] = ua

                _al = __d.get('crh_accept-language')
                if _al is not None:
                    al = getPreferredLocale(_al)

                _xff = __d.get('crh_x-forwarded-for')
                if _xff is not None:
                    try:
                        xff = _xff.split(',')[-1].strip()
                    except:
                        pass

                dnt = __d.get('crh_dnt')

        _ip = xff if (__d['client_ip'].startswith('127.0.') or usexffip) and xff else __d['client_ip']
        client_ip = ip_cache.get(_ip)
        if client_ip is None:
            client_ip = IP(_ip)
            ip_cache[_ip] = client_ip

        increment("{}.meta.parsed-lines.{}".format(prefix, nodename))

        if client_ip.iptype() != 'PRIVATE':
            increment("{}.request.external.{}".format(prefix, nodename))
        else:
            increment("{}.request.internal.{}".format(prefix, nodename))

        # Detect/Handle Spiders/Crawlers
        is_spider = False
        is_img_proxy = False
        is_preview_browser = False

        if ua:
            # Spider
            if ua['device']['family'] == 'Spider':
                is_spider = True
            elif ua['device']['family'] == 'Other' or ua['os']['family'] == 'Other':
                if BOT_PATTERN.match(ua['string']):
                    is_spider = True
                elif IMGPROXY_PATTERN.match(ua['string']):
                    is_img_proxy = True
                elif PREVIEW_PATTERN.match(ua['string']):
                    is_preview_browser = True
        elif ua is None and 'crh_user-agent' in __d and client_ip.iptype() != 'PRIVATE':
            # Empty User-Agent string and none private network - mark it as a spider
            is_spider = True

        # try and do all this in one for-loop
        for backend in ["backend-" + __d['backend_name'], "all-backends"]:

            suffix = "{}.{}".format(nodename, backend.replace(".", "-"))

            if cc_event:
                increment("{}.response.clientabort.status.{}.{}".format(prefix, status_code.lower(), suffix))
            elif cd_event:
                increment("{}.response.clientdisconnect.status.{}.{}".format(prefix, status_code.lower(), suffix))
            else:
                increment("{}.response.status.{}.{}".format(prefix, status_code.lower(), suffix))
            increment("{}.request.method.{}.{}".format(prefix, method.lower(), suffix))

            add_gauge(lock,"{}.bytesread-pct.{}.{}".format(prefix, "{}", suffix),__d['bytes_read'])
            add_gauge(lock,"{}.request-time-pct.{}.{}".format(prefix, "{}", suffix),__d['Tt'])
            if __d['Tr'] > 0:
                add_gauge(lock,"{}.server-time-pct.{}.{}".format(prefix, "{}", suffix),__d['Tr'])

            # speed things up
            if backend == 'backend-normal-varnish' or backend == 'backend-rollout' or backend == 'backend-statushub' or backend == 'backend-geoip_servers' or backend == 'backend-deadhost' or backend == 'backend-search' or backend == 'backend-i2smartlook' or backend == 'backend-hijacked' :
                continue

            if is_spider:
                increment("{}.stats.browser.ua.crawlers.{}".format(prefix, suffix))
                if ua:
                    increment("{}.stats.browser.ua.crawlers.real.{}".format(prefix, suffix))
                    _iua = ua['string'].lower()
                    try:
                        if 'googlebot-news' in _iua:
                            increment("{}.stats.browser.ua.crawlers.googlebot-news.{}".format(prefix, suffix))
                        elif 'googlebot-image' in _iua:
                            increment("{}.stats.browser.ua.crawlers.googlebot-image.{}".format(prefix, suffix))
                        elif 'googlebot-video' in _iua:
                            increment("{}.stats.browser.ua.crawlers.googlebot-video.{}".format(prefix, suffix))
                        elif 'googlebot-mobile' in _iua:
                            increment("{}.stats.browser.ua.crawlers.googlebot-mobile.{}".format(prefix, suffix))
                        elif 'mediapartners-google' in _iua:
                            increment("{}.stats.browser.ua.crawlers.google-adsense.{}".format(prefix, suffix))
                        elif 'adsbot-google' in _iua:
                            increment("{}.stats.browser.ua.crawlers.google-adsbot.{}".format(prefix, suffix))
                        elif ua['user_agent']['family'] == 'Googlebot' or 'google' in _iua:
                            if 'googlebot' in verifybot:
                                if not verifyGoogleBot(client_ip):
                                    increment("{}.stats.browser.ua.crawlers.fake-googlebot.{}".format(prefix, suffix))
                                else:
                                    increment("{}.stats.browser.ua.crawlers.real-googlebot.{}".format(prefix, suffix))
                            increment("{}.stats.browser.ua.crawlers.googlebot.{}".format(prefix, suffix))
                        elif 'bingbot' in _iua:
                            if 'bingbot' in verifybot:
                                if not verifyBingBot(client_ip):
                                    increment("{}.stats.browser.ua.crawlers.fake-bingbot.{}".format(prefix, suffix))
                                else:
                                    increment("{}.stats.browser.ua.crawlers.real-bingbot.{}".format(prefix, suffix))
                            increment("{}.stats.browser.ua.crawlers.bingbot.{}".format(prefix, suffix))
                        elif 'yahoo! slurp' in _iua:
                            increment("{}.stats.browser.ua.crawlers.yahoo.{}".format(prefix, suffix))
                        elif 'baiduspider' in _iua:
                            increment("{}.stats.browser.ua.crawlers.baiduspider.{}".format(prefix, suffix))
                        elif 'yandexbot' in _iua:
                            increment("{}.stats.browser.ua.crawlers.yandex.{}".format(prefix, suffix))
                        elif 'python' in _iua:
                            increment("{}.stats.browser.ua.crawlers.python.{}".format(prefix, suffix))
                        elif 'clickagy' in _iua:
                            increment("{}.stats.browser.ua.crawlers.clickagy.{}".format(prefix, suffix))
                        elif 'twitterbot' in _iua:
                            increment("{}.stats.browser.ua.crawlers.twitterbot.{}".format(prefix, suffix))
                        elif 'whatsapp' in _iua:
                            increment("{}.stats.browser.ua.crawlers.whatsapp.{}".format(prefix, suffix))
                        elif 'turnitinbot' in _iua:
                            increment("{}.stats.browser.ua.crawlers.turnitinbot.{}".format(prefix, suffix))
                        elif 'getintent' in _iua:
                            increment("{}.stats.browser.ua.crawlers.getintent.{}".format(prefix, suffix))
                        elif 'coldfusion' in _iua:
                            increment("{}.stats.browser.ua.crawlers.coldfusion.{}".format(prefix, suffix))
                        elif 'sentry' in _iua:
                            increment("{}.stats.browser.ua.crawlers.sentry.{}".format(prefix, suffix))
                        elif 'java' in _iua:
                            increment("{}.stats.browser.ua.crawlers.java.{}".format(prefix, suffix))
                        elif 'curl' in _iua:
                            increment("{}.stats.browser.ua.crawlers.curl.{}".format(prefix, suffix))
                        elif 'nutch' in _iua:
                            increment("{}.stats.browser.ua.crawlers.nutch.{}".format(prefix, suffix))
                        elif 'node-fetch' in _iua:
                            increment("{}.stats.browser.ua.crawlers.node-fetch.{}".format(prefix, suffix))
                        elif 'facebook' in _iua:
                            increment("{}.stats.browser.ua.crawlers.facebook.{}".format(prefix, suffix))
                        elif 'pinterest' in _iua:
                            increment("{}.stats.browser.ua.crawlers.pinterest.{}".format(prefix, suffix))
                        elif 'opensiteexplorer' in _iua:
                            increment("{}.stats.browser.ua.crawlers.opensiteexplorer.{}".format(prefix, suffix))
                        elif 'seznambot' in _iua:
                            increment("{}.stats.browser.ua.crawlers.seznambot.{}".format(prefix, suffix))
                        elif 'siteimprove' in _iua:
                            increment("{}.stats.browser.ua.crawlers.siteimprove.{}".format(prefix, suffix))
                        elif 'archive-it' in _iua:
                            increment("{}.stats.browser.ua.crawlers.archive-it.{}".format(prefix, suffix))
                        elif 'mj12bot' in _iua:
                            increment("{}.stats.browser.ua.crawlers.mj12bot.{}".format(prefix, suffix))
                        else:
                            increment("{}.stats.browser.ua.crawlers.other.{}".format(prefix, suffix))
                    except:
                        pass
                else:
                    increment("{}.stats.browser.ua.crawlers.empty-ua.{}".format(prefix, suffix))
                if sc >= 400 and sc <= 499:
                    increment("{}.response.status.crawlers.4xx.{}".format(prefix, suffix))
                    if sc in [400,401,403,404]:
                        increment("{}.response.status.crawlers.4xx.{}.{}".format(prefix, sc, suffix))
                elif sc >= 500 and sc <= 599:
                    increment("{}.response.status.crawlers.5xx.{}".format(prefix, suffix))
                    if sc in [500,502,503,504]:
                        increment("{}.response.status.crawlers.5xx.{}.{}".format(prefix, sc, suffix))

            elif is_img_proxy:
                increment("{}.stats.browser.ua.imgproxy.{}".format(prefix, suffix))
                if ua:
                    try:
                        if 'GoogleImageProxy' in ua['string']:
                            increment("{}.stats.browser.ua.imgproxy.google.{}".format(prefix, suffix))
                    except:
                        pass

            elif is_preview_browser:
                increment("{}.stats.browser.ua.preview.{}".format(prefix, suffix))
                if ua:
                    try:
                        if 'Google' in ua['string']:
                                increment("{}.stats.browser.ua.preview.google.{}".format(prefix, suffix))
                    except:
                        pass

            else:
                if ua:
                    try:
                        # OS Family, i.e. Windows 7, Windows 2000, iOS, Android, Mac OS X, Windows Phone, Windows Mobile
                        os_family=ua['os']['family']
                        os_familyname=os_family.split(' ')[0]
                        if os_familyname == 'Windows':
                            if os_family in ['Windows Phone', 'Windows Mobile']:
                                increment("{}.stats.browser.ua.os.windows-phone.{}".format(prefix, suffix))
                            else:
                                increment("{}.stats.browser.ua.os.windows.{}".format(prefix, suffix))
                        elif os_family == 'iOS':
                            increment("{}.stats.browser.ua.os.ios.{}".format(prefix, suffix))
                        elif os_family == 'Android':
                            increment("{}.stats.browser.ua.os.android.{}".format(prefix, suffix))
                        elif os_family in ['Mac OS X', 'Mac OS']:
                            increment("{}.stats.browser.ua.os.mac-os-x.{}".format(prefix, suffix))
                        elif os_family in LINUX_VARIANTS:
                            increment("{}.stats.browser.ua.os.linux.{}".format(prefix, suffix))
                        elif os_familyname == 'BlackBerry':
                            increment("{}.stats.browser.ua.os.blackberry.{}".format(prefix, suffix))
                        elif 'CFNetwork' in ua['string']:
                            increment("{}.stats.browser.ua.cfnetwork.{}".format(prefix, suffix))
                        else:
                            increment("{}.stats.browser.ua.os.other.{}".format(prefix, suffix))
                    except:
                        increment("{}.stats.browser.ua.os.other.{}".format(prefix, suffix))

        if al and not is_spider and not is_img_proxy and not is_preview_browser:
            if al in LANGUAGES:
                increment("{}.stats.browser.language.{}.{}".format(prefix, al.lower(), nodename))
            else:
                increment("{}.stats.browser.language.{}.{}".format(prefix, 'other', nodename))

        if dnt:
            if not is_spider and not is_img_proxy and not is_preview_browser:
                if dnt in ["1","TRUE","True","true"]:
                    increment("{}.stats.browser.dnt.true.{}".format(prefix, nodename))
                elif dnt in ["0","FALSE","False","false"]:
                    increment("{}.stats.browser.dnt.false.{}".format(prefix, nodename))
                else:
                    increment("{}.stats.browser.dnt.other.{}".format(prefix, nodename))
            else:
                increment("{}.stats.browser.dnt.crawler.{}".format(prefix, nodename))
        elif headers and 'dnt' in headers:
            increment("{}.stats.browser.dnt.unset.{}".format(prefix, nodename))

        if not is_spider and not is_img_proxy and not is_preview_browser:
            if client_ip.iptype() != 'PRIVATE' and __d['backend_name'] != 'statistics':
                if __d['server_name'] != '<NOSRV>':
                    try:
                        ip_counter['backend-'+__d['backend_name']][client_ip.ip] += 1
                    except:
                        ip_counter['backend-'+__d['backend_name']][client_ip.ip] = 1
                try:
                    ip_counter['all-backends'][client_ip.ip] += 1
                except:
                    ip_counter['all-backends'][client_ip.ip] = 1

        try:
            __iu = urlparse(__d['path'])
        except:
            __iu = None

#        if __iu is not None:
#            if __d['server_name'] != '<NOSRV>':
#                try:
#                    url_counter['backend-'+__d['backend_name']][__iu.path] += 1
#                except:
#                    url_counter['backend-'+__d['backend_name']][__iu.path] = 1
#            try:
#                url_counter['all-backends'][__iu.path] += 1
#            except:
#                url_counter['all-backends'][__iu.path] = 1

        # skip redirects ?
        if (magma or issuu) and sc > 0 and __iu is not None:
            try:
                if magma:
                    if __iu.path == "/":
                        urlstat(__d, "root")
                    else:
                        for __p in magma_patterns:
                            if __p['pattern'].match(__iu.path):
                                urlstat(__d, __p['metric'])
                                break

                if issuu:
                    if __iu.path == "/":
                        urlstat(__d, "root")
                    elif ISSUUDOC_PATTERN.match(__iu.path):
                        urlstat(__d, "docs")
                    elif ISSUUSEARCH_PATTERN.match(__iu.path):
                        urlstat(__d, "search")
                    elif ISSUUPUBLISH_PATTERN.match(__iu.path):
                        urlstat(__d, "publish")
                    elif ISSUUQUERY_PATTERN.match(__iu.path):
                        urlstat(__d, "api-query")
                    elif ISSUUSTACKS_PATTERN.match(__iu.path):
                        urlstat(__d, "stacks")
                    elif ISSUUFOLLOWERS_PATTERN.match(__iu.path):
                        urlstat(__d, "followers")
                    elif ISSUUEXPLORE_PATTERN.match(__iu.path):
                        urlstat(__d, "explore")
                    elif ISSUUPRICING_PATTERN.match(__iu.path):
                        urlstat(__d, "pricing")
                    elif ISSUUEMAILREJECTED_PATTERN.match(__iu.path):
                        urlstat(__d, "emailrejected")
                    elif ISSUUOPTOUT_PATTERN.match(__iu.path):
                        urlstat(__d, "optout")
                    elif ISSUUCLAIM_PATTERN.match(__iu.path):
                        urlstat(__d, "claim-account")
                    elif ISSUUOEMBED_PATTERN.match(__iu.path):
                        urlstat(__d, "oembed")
                    elif ISSUUMULTIPART_PATTERN.match(__iu.path):
                        urlstat(__d, "multipart")
                    elif ISSUUSIGNIN_PATTERN.match(__iu.path):
                        urlstat(__d, "signin")
                    elif ISSUUSIGNUP_PATTERN.match(__iu.path):
                        urlstat(__d, "signup")
                    elif ISSUUFBAPP_PATTERN.match(__iu.path):
                        urlstat(__d, "fbapp")
                    else:
                        __im = ISSUUCALL_PATTERN.match(__iu.path)
                        if __im:
                            __ip = __im.groupdict()['subcall'].replace(".", "-")
                            urlstat(__d, "api-call")
                            if __ip:
                                if __ip in ISSUU_THINLAYER_CALLS:
                                    urlstat(__d, "api-call."+__ip)
                                else:
                                    urlstat(__d, "api-call.other")
                        else:
                            __im = ISSUUHOME_PATTERN.match(__iu.path)
                            if __im or __iu.path == "/home" or __iu.path == "/home/":
                                urlstat(__d, "home")
                                if __iu.path == "/home" or __iu.path == "/home/":
                                    __ip = "root"
                                    urlstat(__d, "home."+__ip)
                                else:
                                    __ip = __im.groupdict()['subhome'].replace(".", "-")
                                    if __ip:
                                        if __ip in ISSUU_HOME_CALLS:
                                            urlstat(__d, "home."+__ip)
                                        else:
                                            urlstat(__d, "home.other")
                            else:
                                __im = ISSUUPIXEL_PATTERN.match(__iu.path)
                                if __im or __iu.path == "/v1" or __iu.path == "/v1/":
                                    urlstat(__d, "pixeltrack")
                                    if __iu.path == "/v1" or __iu.path == "/v1/":
                                        __ip = "root"
                                    else:
                                        __ip = __im.groupdict()['pixel'].replace(".", "-")
                                    if __ip:
                                        urlstat(__d, "pixeltrack."+__ip)
                                else:
                                    __im = ISSUUPUBLISHERSTORE_PATTERN.match(__iu.path)
                                    if __im or __iu.path == "/store" or __iu.path == "/store/":
                                        urlstat(__d, "store")
                                        if __iu.path == "/store" or __iu.path == "/store/":
                                            __ip = "root"
                                            urlstat(__d, "store."+__ip)
                                        else:
                                            __ip = __im.groupdict()['publisher'].replace(".", "-")
                                            if __ip:
                                                urlstat(__d, "store.publisher."+__ip)

            except Exception as e:
                print >> sys.stderr, e
                increment("{}.meta.exceptions.{}".format(prefix, nodename))
                pass

    else:
        __m = updown_pattern.match(line)
        if __m:
            __d = __m.groupdict()
            for backend in ["backend-" + __d['backend_name'], "all-backends"]:
                suffix = "{}.{}".format(nodename, backend.replace(".", "-"))
                if __d['updown'] == 'DOWN' or __d['updown'] == 'UP':
                    increment("{}.meta.up-down.{}".format(prefix, suffix))
                else:
                    print >> sys.stderr, 'Failed to parse line: %s' % line
                    increment("{}.meta.unparsed-lines.{}".format(prefix, nodename))
        else:
            __m = health_pattern.match(line)
            if __m:
                __d = __m.groupdict()
                counters["{}.meta.health-notice.{}".format(prefix, nodename)] = 1
            else:
                __m = startstop_pattern.match(line)
                if __m:
                    __d = __m.groupdict()
                    counters["{}.meta.start-stop.{}".format(prefix, nodename)] = 1
                else:
                    __m = noserver_pattern.match(line)
                    if __m:
                        __d = __m.groupdict()
                        for backend in ["backend-" + __d['backend_name'], "all-backends"]:
                            suffix = "{}.{}".format(nodename, backend.replace(".", "-"))
                            increment("{}.meta.noserver.{}".format(prefix, suffix))
                    else:
                        #raise LogsterParsingException, "Failed to parse line: %s" % line
                        print >> sys.stderr, 'Failed to parse line: %s' % line
                        increment("{}.meta.unparsed-lines.{}".format(prefix, nodename))

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

class ThreadedHaProxyLogster(LogsterParser):
    '''ThreadedHaProxyLogster'''
    def __init__(self, option_string=None):

        global issuu
        global magma
        global usexffip
        global headers
        global verifybot
        global log_line_pattern
        global updown_pattern
        global health_pattern
        global startstop_pattern
        global noserver_pattern

        if option_string:
            options = option_string.split(' ')
        else:
            options = []

        optparser = optparse.OptionParser()
        optparser.add_option('--socket', '-s', dest='pxy_socket', default=None,
                            help='HaProxy Unix Socket')
        optparser.add_option('--headers', '-x', dest='headers', default=None,
                            help='HaProxy Captured Request Headers in a comma separated list')
        optparser.add_option('--issuu', '-i', dest='issuu', action="store_true", default=False,
                            help='Special parsing of Issuu paths, i.e. /<account>/docs/<document>')
        optparser.add_option('--magma', '-m', dest='magma', action="store_true", default=False,
                            help='Special parsing of Magma paths')
        optparser.add_option('--xffip', '-f', dest='usexffip', action="store_true", default=False,
                            help='Use X-Forwarded-For value for the client-ip (useful if behind another proxy like ELB)')
        optparser.add_option('--verifybot', '-b', dest='verifybot', default=None,
                            help='Verify the bot identity - reverse dns. A comma separated list: googlebot, bingbot')

        opts, args = optparser.parse_args(args=options)

        issuu = opts.issuu
        magma = opts.magma
        usexffip = opts.usexffip
        if opts.headers:
            headers = [x.lower() for x in opts.headers.split(',')]
 
        if opts.pxy_socket is None:
            print >> sys.stderr, 'Missing --socket option'
            raise Exception("Missing --socket option")

        verifybot = []
        if opts.verifybot:
            verifybot = [x.lower() for x in opts.verifybot.split(',')]

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
        # - or
        #2015-08-31T14:27:15.868400+00:00 prod-web-proxy haproxy[3488]: INFO 10.141.243.144:39290
        reset_pattern()
        add_pattern('log_time', r'(\S+( |  )\d+ \d+:\d+:\d+|\d+\-\d+\-\d+T\d+:\d+:\d+\.\d+\+\d+:\d+)')
        add_pattern('hostname', r'\S+')
        add_pattern('process_id', r'\S+', ': ')

        # INFO
        add_pattern('level', r'([^0-9]+)?')

        # 67.22.131.95:39339 '
        # ::ffff:127.0.0.1
        add_pattern('client_ip', r'([\S+])?(::ffff:)?\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}', ':')
        add_pattern('client_port', r'\d+')

        #[29/Nov/2012:14:26:47.198] '
        add_pattern('accept_date', r'\[\S+\]')

        # www or www~ (if ssl)
        add_pattern('frontend_name', r'\S+[~]?')

        # normal/wwwA or www/<NOSRV>
        add_pattern('backend_name', r'\S+', '/')
        add_pattern('server_name', r'\S+')

        # 4/0/1/41/47
        add_pattern('Tq', r'[-+]?\d+', '/')
        add_pattern('Tw', r'[-+]?\d+', '/')
        add_pattern('Tc', r'[-+]?\d+', '/')
        add_pattern('Tr', r'[-+]?\d+', '/')
        add_pattern('Tt', r'[-+]?\d+')

        # 404 (-1 and 0 also seen in rare cases)
        add_pattern('status_code', r'(-1|0|\d{3})')

        # 10530 - If "option logasap" is specified, the
        # this value will be prefixed with a '+'
        add_pattern('bytes_read', r'[+]?\d+')
        bytes_read = PercentileMetric()

        # -
        add_pattern('captured_request_cookie', r'(-|\S+)')

        # -
        add_pattern('captured_response_cookie', r'(-|\S+)')

        # --NN
        add_pattern('term_event', r'\S', '')
        add_pattern('term_session', r'\S', '')
        add_pattern('client_cookie', r'\S', '')
        add_pattern('server_cookie', r'\S')

        # 392/391/13/1/0
        add_pattern('total_conns', r'\d+', '/')
        add_pattern('frontend_conns', r'\d+', '/')
        add_pattern('backend_conns', r'\d+', '/')
        add_pattern('srv_conns', r'\d+', '/')
        #This field may optionally be prefixed with a '+' sign,
        #indicating that the session has experienced a redispatch.
        add_pattern('retries', r'[+]?\d+')

        # 0/0
        add_pattern(r'server_queue', r'\d+', '/')
        add_pattern(r'backend_queue', r'\d+')
        # {||||Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.9.1.1) Gecko/20090715 Firefox/3.5.1}
        add_pattern('captured_request_headers', r'([^}]*|)', r'(\} |)', r'(\{|)')

        # {}
        add_pattern('captured_response_headers', r'([^}]*|)', r'(\} |)', r'(\{|)')

        #"GET /goodiesbasket HTTP/1.1" or "<BADREQ>"
        # This final line might not be complete (truncated 1024 buffer)
        add_pattern('method', r'\S+', r'( |")', r'"')
        add_pattern('path', r'\S*', r'( |)')
        add_pattern('protocol', r'.*?', r'("|)')

        # the final regex for HAProxy lines
        log_line_pattern = build_pattern()


        #
        # Up/Down log lines
        # 2016-08-02T07:29:16.860473+00:00 wwwproxy-1 haproxy[726]: ALERT Backup Server normal/www5 is DOWN. 3 active and 2 backup servers left. 0 sessions active, 0 requeued, 0 remaining in queue.
        # 2016-08-02T07:33:13.129175+00:00 wwwproxy-1 haproxy[726]: NOTICE Server crawler/www5 is UP. 3 active and 0 backup servers online. 0 sessions requeued, 0 total in queue.
        #
        reset_pattern()
        add_pattern('log_time', r'(\S+( |  )\d+ \d+:\d+:\d+|\d+\-\d+\-\d+T\d+:\d+:\d+\.\d+\+\d+:\d+)')
        add_pattern('hostname', r'\S+')
        add_pattern('process_id', r'\S+', ': ')
        add_pattern('level', r'\S+')

        # (Backup Server|Server) normal/wwwA or www/<NOSRV>
        add_pattern('backend_name', r'\S+', '/', r'(Backup Server|Server) ')
        add_pattern('server_name', r'\S+')

        #is UP/DOWN, reason:
        add_pattern('updown', r'\S+', ', ', 'is ')
        add_pattern('reason', r'[^,]+', ', ', 'reason: ')

        # skip the rest ...
        add_pattern('skipped', r'.*','')
        updown_pattern = build_pattern()

        #
        # Health Check Notice
        # 2016-08-02T07:33:25.808096+00:00 wwwproxy-1 haproxy[726]: NOTICE Health check for backup server normal/www6 succeeded, reason: Layer7 check passed, code: 200, info: "OK", check duration: 329ms, status: 1/2 DOWN.
        # 2016-08-02T07:33:25.822150+00:00 wwwproxy-1 haproxy[726]: NOTICE Health check for server crawler/www6 succeeded, reason: Layer7 check passed, code: 200, info: "OK", check duration: 242ms, status: 1/2 DOWN.
        #
        reset_pattern()
        add_pattern('log_time', r'(\S+( |  )\d+ \d+:\d+:\d+|\d+\-\d+\-\d+T\d+:\d+:\d+\.\d+\+\d+:\d+)')
        add_pattern('hostname', r'\S+')
        add_pattern('process_id', r'\S+', ': ')
        add_pattern('level', r'\S+')

        # Health check ....
        add_pattern('backend_name', r'\S+', '/', r'Health check for (backup server|server) ')
        add_pattern('server_name', r'\S+')

        #succeeded/failed, reason:
        add_pattern('check', r'\S+', ', ')
        add_pattern('reason', r'[^,]+', ', ', 'reason: ')

        # skip the rest ...
        add_pattern('skipped', r'.*','')
        health_pattern = build_pattern()

        #
        # Start/Stop/Pause log lines
        #
        reset_pattern()
        # start/stop/pause haproxy
        add_pattern('log_time', r'(\S+( |  )\d+ \d+:\d+:\d+|\d+\-\d+\-\d+T\d+:\d+:\d+\.\d+\+\d+:\d+)')
        add_pattern('hostname', r'\S+')
        add_pattern('process_id', r'\S+', ': ')
        add_pattern('level', r'\S+')
        add_pattern('startstop', r'(Proxy \S+ started\.|Pausing proxy \S+\.|Stopping (backend|proxy) \S+ in \d+ \S+\.|Proxy \S+ stopped \([^)]+\)\.)','')
        startstop_pattern = build_pattern()

        #
        # no server available
        #
        reset_pattern()
        # start/stop/pause haproxy
        add_pattern('log_time', r'(\S+( |  )\d+ \d+:\d+:\d+|\d+\-\d+\-\d+T\d+:\d+:\d+\.\d+\+\d+:\d+)')
        add_pattern('hostname', r'\S+')
        add_pattern('process_id', r'\S+', ': ')
        add_pattern('level', r'\S+')
        add_pattern('backend_name', r'\S+', ' ', 'backend ')
        # skip the rest ...
        add_pattern('skipped', r'.*','', 'has no server available!')
        noserver_pattern = build_pattern()

        self.parsed_lines = 0
        self.unparsed_lines = 0

        # initialize counters - always send a value
        counters["{}.meta.parsed-lines.{}".format(prefix, nodename)] = 0
        counters["{}.meta.unparsed-lines.{}".format(prefix, nodename)] = 0
        counters["{}.meta.start-stop.{}".format(prefix, nodename)] = 0
        counters["{}.meta.health-notice.{}".format(prefix, nodename)] = 0
        counters["{}.meta.exceptions.{}".format(prefix, nodename)] = 0

        counters["{}.stats.cur-conns.{}".format(prefix, nodename)] = int(ha_info['CurrConns'])
        counters["{}.stats.tasks.{}".format(prefix, nodename)] = int(ha_info['Tasks'])
        counters["{}.stats.run-queue.{}".format(prefix, nodename)] = int(ha_info['Run_queue'])

        counters["{}.request.internal.{}".format(prefix, nodename)] = 0
        counters["{}.request.external.{}".format(prefix, nodename)] = 0
        counters["{}.request.tarpit.{}".format(prefix, nodename)] = 0
        counters["{}.request.block.{}".format(prefix, nodename)] = 0

        if issuu:
            for u in ["root","docs","stacks","followers","search","publish","explore","api-query","multipart","signin","signup","fbapp"]:
                counters["{}.request.url.{}.crawlers.{}".format(prefix, u, nodename)] = 0
                counters["{}.request.url.{}.crawlers.3xx.{}".format(prefix, u, nodename)] = 0
                counters["{}.request.url.{}.crawlers.3xx.301.{}".format(prefix, u, nodename)] = 0
                counters["{}.request.url.{}.crawlers.3xx.302.{}".format(prefix, u, nodename)] = 0
                counters["{}.request.url.{}.crawlers.3xx.304.{}".format(prefix, u, nodename)] = 0
                counters["{}.request.url.{}.crawlers.4xx.{}".format(prefix, u, nodename)] = 0
                counters["{}.request.url.{}.crawlers.4xx.400.{}".format(prefix, u, nodename)] = 0
                counters["{}.request.url.{}.crawlers.4xx.401.{}".format(prefix, u, nodename)] = 0
                counters["{}.request.url.{}.crawlers.4xx.403.{}".format(prefix, u, nodename)] = 0
                counters["{}.request.url.{}.crawlers.4xx.404.{}".format(prefix, u, nodename)] = 0
                counters["{}.request.url.{}.crawlers.5xx.{}".format(prefix, u, nodename)] = 0
                counters["{}.request.url.{}.crawlers.5xx.500.{}".format(prefix, u, nodename)] = 0
                counters["{}.request.url.{}.crawlers.5xx.502.{}".format(prefix, u, nodename)] = 0
                counters["{}.request.url.{}.crawlers.5xx.503.{}".format(prefix, u, nodename)] = 0
                counters["{}.request.url.{}.crawlers.5xx.504.{}".format(prefix, u, nodename)] = 0
                counters["{}.request.url.{}.non-crawlers.{}".format(prefix, u, nodename)] = 0
                counters["{}.request.url.{}.non-crawlers.3xx.{}".format(prefix, u, nodename)] = 0
                counters["{}.request.url.{}.non-crawlers.3xx.301.{}".format(prefix, u, nodename)] = 0
                counters["{}.request.url.{}.non-crawlers.3xx.302.{}".format(prefix, u, nodename)] = 0
                counters["{}.request.url.{}.non-crawlers.3xx.304.{}".format(prefix, u, nodename)] = 0
                counters["{}.request.url.{}.non-crawlers.4xx.{}".format(prefix, u, nodename)] = 0
                counters["{}.request.url.{}.non-crawlers.4xx.400.{}".format(prefix, u, nodename)] = 0
                counters["{}.request.url.{}.non-crawlers.4xx.401.{}".format(prefix, u, nodename)] = 0
                counters["{}.request.url.{}.non-crawlers.4xx.403.{}".format(prefix, u, nodename)] = 0
                counters["{}.request.url.{}.non-crawlers.4xx.404.{}".format(prefix, u, nodename)] = 0
                counters["{}.request.url.{}.non-crawlers.5xx.{}".format(prefix, u, nodename)] = 0
                counters["{}.request.url.{}.non-crawlers.5xx.500.{}".format(prefix, u, nodename)] = 0
                counters["{}.request.url.{}.non-crawlers.5xx.502.{}".format(prefix, u, nodename)] = 0
                counters["{}.request.url.{}.non-crawlers.5xx.503.{}".format(prefix, u, nodename)] = 0
                counters["{}.request.url.{}.non-crawlers.5xx.504.{}".format(prefix, u, nodename)] = 0

        if headers:
            if 'user-agent' in headers:
                # for each known backend - initialize counters
                for backend in map(lambda x: "backend-"+x['backend'], filter(lambda y: y['srvname'] == 'BACKEND', ha_stats)) + ["all-backends"]:
                    suffix = "{}.{}".format(nodename, backend.replace(".", "-"))
                    counters["{}.stats.browser.ua.crawlers.{}".format(prefix, suffix)] = 0
                    counters["{}.stats.browser.ua.crawlers.real.{}".format(prefix, suffix)] = 0
                    counters["{}.stats.browser.ua.crawlers.other.{}".format(prefix, suffix)] = 0
                    counters["{}.stats.browser.ua.crawlers.fake-googlebot.{}".format(prefix, suffix)] = 0
                    counters["{}.stats.browser.ua.crawlers.real-googlebot.{}".format(prefix, suffix)] = 0
                    counters["{}.stats.browser.ua.crawlers.googlebot.{}".format(prefix, suffix)] = 0
                    counters["{}.stats.browser.ua.crawlers.googlebot-image.{}".format(prefix, suffix)] = 0
                    counters["{}.stats.browser.ua.crawlers.googlebot-news.{}".format(prefix, suffix)] = 0
                    counters["{}.stats.browser.ua.crawlers.googlebot-video.{}".format(prefix, suffix)] = 0
                    counters["{}.stats.browser.ua.crawlers.googlebot-mobile.{}".format(prefix, suffix)] = 0
                    counters["{}.stats.browser.ua.crawlers.google-adsense.{}".format(prefix, suffix)] = 0
                    counters["{}.stats.browser.ua.crawlers.google-adsbot.{}".format(prefix, suffix)] = 0
                    counters["{}.stats.browser.ua.crawlers.fake-bingbot.{}".format(prefix, suffix)] = 0
                    counters["{}.stats.browser.ua.crawlers.real-bingbot.{}".format(prefix, suffix)] = 0
                    counters["{}.stats.browser.ua.crawlers.bingbot.{}".format(prefix, suffix)] = 0
                    counters["{}.stats.browser.ua.crawlers.yahoo.{}".format(prefix, suffix)] = 0
                    counters["{}.stats.browser.ua.crawlers.baiduspider.{}".format(prefix, suffix)] = 0
                    counters["{}.stats.browser.ua.crawlers.yandex.{}".format(prefix, suffix)] = 0
                    counters["{}.stats.browser.ua.crawlers.facebook.{}".format(prefix, suffix)] = 0
                    counters["{}.stats.browser.ua.crawlers.pinterest.{}".format(prefix, suffix)] = 0
                    counters["{}.stats.browser.ua.crawlers.mj12bot.{}".format(prefix, suffix)] = 0
                    counters["{}.stats.browser.ua.crawlers.curl.{}".format(prefix, suffix)] = 0
                    counters["{}.stats.browser.ua.crawlers.java.{}".format(prefix, suffix)] = 0
                    counters["{}.stats.browser.ua.crawlers.opensiteexplorer.{}".format(prefix, suffix)] = 0
                    counters["{}.stats.browser.ua.crawlers.seznambot.{}".format(prefix, suffix)] = 0
                    counters["{}.stats.browser.ua.crawlers.siteimprove.{}".format(prefix, suffix)] = 0
                    counters["{}.stats.browser.ua.crawlers.archive-it.{}".format(prefix, suffix)] = 0
                    counters["{}.stats.browser.ua.crawlers.python.{}".format(prefix, suffix)] = 0
                    counters["{}.stats.browser.ua.crawlers.sentry.{}".format(prefix, suffix)] = 0
                    counters["{}.stats.browser.ua.crawlers.node-fetch.{}".format(prefix, suffix)] = 0
                    counters["{}.stats.browser.ua.crawlers.nutch.{}".format(prefix, suffix)] = 0
                    counters["{}.stats.browser.ua.crawlers.clickagy.{}".format(prefix, suffix)] = 0
                    counters["{}.stats.browser.ua.crawlers.coldfusion.{}".format(prefix, suffix)] = 0
                    counters["{}.stats.browser.ua.crawlers.twitterbot.{}".format(prefix, suffix)] = 0
                    counters["{}.stats.browser.ua.crawlers.whatsapp.{}".format(prefix, suffix)] = 0
                    counters["{}.stats.browser.ua.crawlers.turnitinbot.{}".format(prefix, suffix)] = 0
                    counters["{}.stats.browser.ua.crawlers.getintent.{}".format(prefix, suffix)] = 0
                    counters["{}.stats.browser.ua.crawlers.empty-ua.{}".format(prefix, suffix)] = 0
                    counters["{}.stats.browser.ua.os.windows-phone.{}".format(prefix, suffix)] = 0
                    counters["{}.stats.browser.ua.os.windows.{}".format(prefix, suffix)] = 0
                    counters["{}.stats.browser.ua.os.ios.{}".format(prefix, suffix)] = 0
                    counters["{}.stats.browser.ua.os.android.{}".format(prefix, suffix)] = 0
                    counters["{}.stats.browser.ua.os.mac-os-x.{}".format(prefix, suffix)] = 0
                    counters["{}.stats.browser.ua.os.linux.{}".format(prefix, suffix)] = 0
                    counters["{}.stats.browser.ua.os.blackberry.{}".format(prefix, suffix)] = 0
                    counters["{}.stats.browser.ua.os.other.{}".format(prefix, suffix)] = 0
                    counters["{}.stats.browser.ua.cfnetwork.{}".format(prefix, suffix)] = 0
                    counters["{}.stats.browser.ua.imgproxy.{}".format(prefix, suffix)] = 0
                    counters["{}.stats.browser.ua.preview.{}".format(prefix, suffix)] = 0
                    counters["{}.stats.browser.ua.imgproxy.google.{}".format(prefix, suffix)] = 0
                    counters["{}.stats.browser.ua.preview.google.{}".format(prefix, suffix)] = 0

                    counters["{}.response.status.crawlers.4xx.{}".format(prefix, suffix)] = 0
                    counters["{}.response.status.crawlers.4xx.400.{}".format(prefix, suffix)] = 0
                    counters["{}.response.status.crawlers.4xx.401.{}".format(prefix, suffix)] = 0
                    counters["{}.response.status.crawlers.4xx.403.{}".format(prefix, suffix)] = 0
                    counters["{}.response.status.crawlers.4xx.404.{}".format(prefix, suffix)] = 0
                    counters["{}.response.status.crawlers.5xx.{}".format(prefix, suffix)] = 0
                    counters["{}.response.status.crawlers.5xx.500.{}".format(prefix, suffix)] = 0
                    counters["{}.response.status.crawlers.5xx.502.{}".format(prefix, suffix)] = 0
                    counters["{}.response.status.crawlers.5xx.503.{}".format(prefix, suffix)] = 0
                    counters["{}.response.status.crawlers.5xx.504.{}".format(prefix, suffix)] = 0

            if 'accept-language' in headers:
                for lang in ['OTHER']+LANGUAGES:
                    counters["{}.stats.browser.language.{}.{}".format(prefix, lang.lower(), nodename)] = 0

            if 'dnt' in headers:
                counters["{}.stats.browser.dnt.true.{}".format(prefix, nodename)] = 0
                counters["{}.stats.browser.dnt.false.{}".format(prefix, nodename)] = 0
                counters["{}.stats.browser.dnt.other.{}".format(prefix, nodename)] = 0
                counters["{}.stats.browser.dnt.crawler.{}".format(prefix, nodename)] = 0
                counters["{}.stats.browser.dnt.unset.{}".format(prefix, nodename)] = 0

        # for each known backend - initialize counters
        for backend in map(lambda x: "backend-"+x['backend'], filter(lambda y: y['srvname'] == 'BACKEND', ha_stats)) + ["all-backends"]:
            suffix = "{}.{}".format(nodename, backend.replace(".", "-"))
            for method in ['BADREQ','OTHER']+REQUEST_METHODS:
                counters["{}.request.method.{}.{}".format(prefix, method.lower(), suffix)] = 0
            for status_code in [str(x) for x in STATUS_CODES] + ['BADREQ','OTHER']:
                counters["{}.response.clientabort.status.{}.{}".format(prefix, status_code.lower(), suffix)] = 0
                counters["{}.response.clientdisconnect.status.{}.{}".format(prefix, status_code.lower(), suffix)] = 0
                counters["{}.response.status.{}.{}".format(prefix, status_code.lower(), suffix)] = 0
            counters["{}.meta.up-down.{}".format(prefix, suffix)] = 0
            counters["{}.meta.noserver.{}".format(prefix, suffix)] = 0
            counters["{}.stats.backend.ip-variance.{}".format(prefix, suffix)] = 0
            counters["{}.stats.backend.url-variance.{}".format(prefix, suffix)] = 0
            ip_counter[backend] = {}
            url_counter[backend] = {}
        for haproxy in filter(lambda y: y['srvname'] == 'BACKEND', ha_stats):
            suffix = "{}.{}".format(nodename, "backend-"+haproxy['backend'].replace(".", "-"))
            counters["{}.stats.backend.queue.{}".format(prefix, suffix)] = haproxy['qcur']
            counters["{}.stats.backend.session-rate.{}".format(prefix, suffix)] = haproxy['rate']
            counters["{}.stats.backend.sessions.{}".format(prefix, suffix)] = haproxy['scur']
            counters["{}.stats.backend.error-response.{}".format(prefix, suffix)] = haproxy['eresp']
            counters["{}.stats.backend.client-aborts.{}".format(prefix, suffix)] = haproxy['cliaborts']
            counters["{}.stats.backend.server-aborts.{}".format(prefix, suffix)] = haproxy['srvaborts']
        for haproxy in filter(lambda y: y['srvname'] == 'FRONTEND', ha_stats):
            suffix = "{}.{}".format(nodename, "frontend-"+haproxy['backend'].replace(".", "-"))
            counters["{}.stats.frontend.session-rate.{}".format(prefix, suffix)] = haproxy['rate']
            counters["{}.stats.frontend.sessions.{}".format(prefix, suffix)] = haproxy['scur']

    def get_state(self, duration):
        '''get_state'''
        global threads

        metrics = []

        for t in threads:
            t.join()

        for backend in ip_counter:
            suffix = "{}.{}".format(nodename, backend.replace(".", "-"))
            variance = 0
            try:
                ips = ip_counter[backend]
                if len(ips) > 0:
                    sample = ips.values()
                    if len(sample) > 0:
                        variance = reduce(lambda x,y: x+y, map(lambda xi: (xi-(float(reduce(lambda x,y : x+y, sample)) / len(sample)))**2, sample))/ len(sample)
            except:
                pass
            counters["{}.stats.backend.ip-variance.{}".format(prefix, suffix)] = int(variance)

# This takes to long time to process
#        for backend in self.url_counter:
#            suffix = "{}.{}".format(nodename, backend.replace(".", "-"))
#            url_variance = 0
#            try:
#                urls = self.url_counter[backend]
#                if len(ips) > 0:
#                    sample = urls.values()
#                    if len(sample) > 0:
#                        url_variance = reduce(lambda x,y: x+y, map(lambda xi: (xi-(float(reduce(lambda x,y : x+y, sample)) / len(sample)))**2, sample))/ len(sample)
#            except:
#                pass
#            counters["{}.stats.backend.url-variance.{}".format(prefix, suffix)] = int(url_variance)

        for name, value in counters.items():
            metrics.append(MetricObject(name, value))

        for name, value in gauges.items():
            metrics.extend(value.as_metrics(name))

        try:
            pickle.dump( ip_cache, open( "/var/tmp/haproxy_logster_ip.p", "wb" ) )
            pickle.dump( ua_cache, open( "/var/tmp/haproxy_logster_ua.p", "wb" ) )
            pickle.dump( bingbot_cache, open( "/var/tmp/haproxy_logster_bingbot.p", "wb" ) )
            pickle.dump( googlebot_cache, open( "/var/tmp/haproxy_logster_googlebot.p", "wb" ) )
        except:
            pass

        return metrics

    def parse_line(self, line):
        '''parse_line'''
        global threads

        if len(threads) > 999:
            for t in threads:
                t.join()
            threads=[]

        t = threading.Thread(target=threaded_parse_line, args=(lock,line,))
        threads.append(t)
        t.start()

