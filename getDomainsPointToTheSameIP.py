import time
import queue
import requests
from publicdns.client import PublicDNS
import concurrent.futures

APIKEY=["<List virustotal apikey come here>","APIKEY2"]

MaxReqPerMin = 4
NumOfAPIKey = len(APIKEY)
TimeToSleep = 60/(NumOfAPIKey*MaxReqPerMin)
domainQueue = queue.Queue()
ipQueue = queue.Queue()
domainSet = set()
ID = {}
originIp = set()

def lookup():
    global ID
    global domainQueue
    global ipQueue
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        listDomain = []
        while not domainQueue.empty():
            listDomain.append(domainQueue.get())
        future_to_ips = {executor.submit(resolve, domain) : domain for domain in listDomain}
        for future in concurrent.futures.as_completed(future_to_ips):
            domain = future_to_ips[future]
            try:
                ips = future.result()
            except Exception as exc:
                continue
            if(ips is None):
                continue
            for ip in ips:
                if(ip in ID):
                    ID[ip] |= {domain}
                else:
                    ID[ip] = set({domain})
                    ipQueue.put(ip)

def resolve(domain):
    print("processing domain: %s" %(domain))
    if domain is None:
        return None
    client = PublicDNS()
    try:
        ips = client.resolve(domain)
    except Exception as e:
        return None
    return ips

def reverseLookup():
    global domainSet
    global ipQueue
    count = 0
    url = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
    while not ipQueue.empty():
        ip = ipQueue.get()
        print("Processing ip %s" %(ip))
        params = {'apikey':APIKEY[count],'ip':ip}
        count = (count + 1) % NumOfAPIKey
        response = requests.get(url, params=params)
        if(response.json()['response_code'] ==0):
            continue
        for domain in response.json()['resolutions']:
            if domain['hostname'] not in domainSet:
                domainQueue.put(domain['hostname'])
                domainSet.add(domain['hostname'])
        time.sleep(TimeToSleep)

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
