import time
import queue
import requests
from publicdns.client import PublicDNS

APIKEY=["<List virustotal apikey come here>"]
MaxReqPerMin = 4
NumOfAPIKey = len(APIKEY)
TimeToSleep = NumOfAPIKey*MaxReqPerMin
domainQueue = queue.Queue()
ipQueue = queue.Queue()
domainSet = set()
ipSet = set()
ID = {}
originIp = set()

def lookup():
    global ID
    global domainQueue
    while not domainQueue.empty():
        domain = domainQueue.get()
        print("processing domain: %s" %(domain))
        client = PublicDNS()
        try:
            ips = client.resolve(domain)
        except Exception as e:
            print(e)
            continue
        for ip in ips:
            if(ip in ID):
                ID[ip].add((domain))
            ID[ip] = set((domain))
            ipQueue.put(ip)

def reverseLookup():
    global domainSet
    count = 0
    global ipQueue
    while not ipQueue.empty():
        ip = ipQueue.get()
        time.sleep(60/TimeToSleep)
        print("Processing ip %s" %(ip))
        url = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
        params = {'apikey':APIKEY[count],'ip':ip}
        count = (count + 1) % NumOfAPIKey
        response = requests.get(url, params=params)
        if(response.json()['response_code'] ==0):
            continue
        for domain in response.json()['resolutions']:
            domainQueue.put(domain['hostname'])
            domainSet.add(domain['hostname'])

def loadDomain():
    global domainQueue
    for line in open("domainList").readlines():
        domain = line.strip()
        domainQueue.put(domain)
        domainSet.add(domain)

loadDomain()
lookup()
[originIp.add(ip) for ip in ID]
reverseLookup()
lookup()
print("Last result:")
[print(ip, " : ",ID[ip],end="\n") for ip in originIp]
