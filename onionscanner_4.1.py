import sys
import getopt
import re
import hashlib
import urllib2
# unused
from requests.auth import HTTPBasicAuth  # apt-get install python-requests
import MySQLdb  # apt-get install python-MySQLdb

from optparse import OptionParser
import socket
import socks  # socksipy
from BeautifulSoup import BeautifulSoup

bufsize = 0
PAGE_HASH = 'acbc159c7062332360bcd792ff9c6e294cb32ec3a5b87577e25da36117518b172f2c77c59c1a9bb18f8d905d1f67eeab9cca217990f23828444c2c9aff865e0b'
SOCKS_PORT = 9050
socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, '127.0.0.1', SOCKS_PORT, True)
socket.setdefaulttimeout(200)
socket.socket = socks.socksocket
socket.getaddrinfo = lambda *x: [(socket.AF_INET, socket.SOCK_STREAM, 6, '', x)]

# Scanning, or loading new onions?
inputfile = ''


def main():
    try:
        cl_options, cl_args = getopt.getopt(sys.argv[1:], "i:")
        for option, arg in cl_options:
            if option == '-i':
                inputfile = arg
                load_onions(inputfile)
            else:
                print("Usage: %s -i onionlist" % sys.argv[0])
                print("onionlost MUST CONTAIN one onion per line, without the .onion in the address")
                print("Use no arguments to run the standard onion scan")
                onion_scan()
    except Exception:
        pass


def fetch_hs(addr):
    try:
        # password_mgr = urllib.request.HTTPPasswordMgrWithDefaultRealm()
        # password_mgr.add_password(None, addr, 'user', 'password')
        # handler = urllib.request.HTTPBasicAuthHandler(password_mgr)
        # opener = urllib.request.build_opener(handler)
        # urllib._urlopener = opener
        print('Trying to retrieve address')
        response = urllib2.urlopen(addr)  # , urlencode({'user': 'user', 'password':'pass'})
        print('Opened URL')
        print(response.info())
        document = response.read()

        print(document)
        return document
    except:
        print("cannot reach address\n")
        print("----------------------")
        return "unreachable"


def test_hash(s):
    sha = hashlib.sha512(s).hexdigest()
    # print('Hash(' + str(len(s)) +") = ", sha)
    if sha == PAGE_HASH:
        print("MATCH", s, )
        exit()
    return sha


def load_onions(inputfile):
    add_onion = """INSERT INTO tblCollectedOnions
    (onion_addr, source)
    VALUES(%s, %s)"""
    try:
        print('Connecting to DB')
        sslopts = {'cert': '/opt/mysql/newcerts/client-cert.pem', 'key': '/opt/mysql/newcerts/client-key.pem'}
        dbconnection = MySQLdb.connect(user='mysql', passwd='jk3mADFL%# @3', db='scandb', unix_socket='/var/run/mysqld/mysqld.sock', ssl=sslopts)
    except MySQLdb.Error as err:
        print(err)
    else:
        print('Establishing cursor')
        dbcursor = dbconnection.cursor()
        print('Inserting New Onions...')
        regex = re.compile("^([a-z2-7]){16}$")
        infile = open(inputfile, "r+")
        with open(infile, "r+") as onionlist:
            onion_addr = onionlist.read()
            if not onion_addr:
                onionlist.close()
# ## ## FIXME U FOKN WOT M8?! THERE AINT NO LOOP IN HERE INNIT
                # break  # Don't capture blank line
            else:
                if regex.match(onion_addr):
                    data_onion = (onion_addr, inputfile)
                    dbcursor.execute(add_onion, data_onion)
                    dbconnection.commit()
            onionlist.close()
        infile.close()
        dbcursor.close()
        dbconnection.close()


def onion_scan():
    add_onionscan = """INSERT INTO tblOnionScan
                        (onion_addr, working, contents, title, sha1_hash)
                        VALUES(%s, %s, %s, %s, %s)"""

    try:
        print('Connecting to DB')
        sslopts = {'cert': '/opt/mysql/newcerts/client-cert.pem', 'key': '/opt/mysql/newcerts/client-key.pem'}
        dbconnection = MySQLdb.connect(user='mysql', passwd='jk3mADFL%# @3', db='scandb', unix_socket='/var/run/mysqld/mysqld.sock', ssl=sslopts)
    except MySQLdb.Error as err:
        print(err)
    else:
        print('Establishing cursor')
        dbcursor = dbconnection.cursor()
        print('Querying...')
        query = ("SELECT DISTINCT tco.onion_addr from tblCollectedOnions AS tco WHERE tco.onion_addr NOT IN (SELECT DISTINCT tos.onion_addr FROM tblOnionScan AS tos) ORDER BY tco.onion_addr")
        dbcursor.execute(query)
        for onion_addr in dbcursor:
            print("----------------------")
            onionurl = "http://" + onion_addr[0] + ".onion"
            print(onionurl)
            contents = fetch_hs(onionurl)
            if contents != "unreachable":
                contenthash = test_hash(contents)
                print("Success")
                parsedcontents = contents
                try:
                    parsedcontents = BeautifulSoup(contents)
                except:
                    parsedcontents = contents
                pagetitle = ""
                if (parsedcontents.title is None) | (parsedcontents.title == ""):  # | (parsedcontents.title.string=="") | (parsedcontents.title.string is None):
                    pagetitle = ""
                else:
                    pagetitle = parsedcontents.title.string
                #   print(pagetitle.encode('utf-8'))
                data_onionscan = (
                    onion_addr[0],
                    'true',
                    contents,
                    pagetitle,
                    contenthash)
                print(data_onionscan)
                dbcursor.execute(add_onionscan, data_onionscan)
                dbconnection.commit()
            else:
                print("Content unreachable")
                data_onionscan = (
                    onion_addr[0],
                    'false',
                    contents, '', '')
                print(data_onionscan)
                dbcursor.execute(add_onionscan, data_onionscan)
                dbconnection.commit()
        dbcursor.close()
        dbconnection.close()


main()


# convert hostname to IP
def convertHostnameToIP(hostname):
    try:
        # FIXME undef
        ip = gethostbyname(hostname)
        return ip
    except Exception:
        return None


def connectTo(hostname, port):
    try:
        # FIXME undef
        openSocket = socket(AF_INET, SOCK_STREAM)  # open TCP socket
        openSocket.connect((hostname, port))
        return openSocket
    except:
        openSocket.close()
        return None


def grabBanner(openSocket):
    try:
        openSocket.send("Raise your banners!\r\n")
        banner = openSocket.recv(2048)
        return banner
    except:
        return None


def scanHost(hostname, port):
    openSocket = connectTo(hostname, port)
    # FIXME undef
    setdefaulttimeout(10)
    if openSocket:
        print("[+](Connected to %s:%d" % (host, port))
        banner = grabBanner(openSocket)
        if banner:
            print(("[+] Banner: %s" % banner))
        else:
            print(("[!] Can't grab the target banner"))
        openSocket.close()
    else:
        print("[!](Can't connect to %s:%d" % (host, port))


# MOdify

if __name__ == "__main__":
    parser = OptionParser()
    parser.add_option("-t", "--target", dest="host", type="string",
                      help="enter host name", metavar="exemple.com")
    parser.add_option("-p", "--port", dest="ports", type="string",
                      help="port you want to scan separated by comma", metavar="PORT")

    (options, args) = parser.parse_args()

    if options.host is None or options.ports is None:
        parser.print_help()
    else:
        host = options.host
        ports = (options.ports).split(", ")
        try:
            ports = list(filter(int, ports))  # Store ports into list
            # FIXME undef
            ip = h2ip(host)  # Domain name to IP
            if ip:
                print("[+] Running scan on %s" % host)
                print("[+] Target IP: %s" % ip)
                for port in ports:
                    # FIXME undef
                    scan(host, int(port))
            else:
                print("[!] Invalid host")
        except:
            print("[!] Invalid port list (e.g: -p 21, 22, 53, ..)")
