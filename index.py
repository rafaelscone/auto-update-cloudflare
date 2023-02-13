#!/usr/bin/env python3

import json
import urllib.error
import urllib.parse
import urllib.request
from configparser import ConfigParser
from os import path
import threading
import time
import requests
import os
import sys
import socket
import datetime
import jwt

# Others
import CloudFlare
from configparser import ConfigParser

# Import .env variables
from dotenv import load_dotenv
load_dotenv()

# Vars
URL_CHECK_IP = os.getenv('URL_CHECK_IP')
CLOUDFLARE_TOKEN= os.getenv('CLOUDFLARE_TOKEN')
JWT_SECRET = os.getenv('JWT_SECRET')
API_KEY = os.getenv('API_KEY')
DOMAINS= os.getenv('DOMAINS')
REGISTER_LOCAL= os.getenv('REGISTER_LOCAL')
TIME_UPDATE= os.getenv('TIME_UPDATE')
WEEBHOOK= os.getenv('WEEBHOOK')

def do_request(url,headers =False ):
    if headers == False:
        headers= {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:75.0) Gecko/20100101 Firefox/75.0"
        }
    try:
        
        r = requests.get(url,headers= headers)
        text = r.text
        #print(r.text)
        if r.status_code != 200 or type(text) is not str:
            return False
        return text
    except:
        return False
def convert_json(data):
    try:
        return json.loads(data)
    except:
        return False
def get_public_ip():
    headers = {}
    if JWT_SECRET is not None:
        data = {
            "func": "cloud_flare_dns_update",
            "domains": DOMAINS
        }
        jwt_token = generate_jwt_token(JWT_SECRET,data)
        headers['Authorization'] = f"Bearer {jwt_token}"
    if API_KEY is not None:
        headers['x-api-key']= API_KEY

    ip = convert_json(do_request(URL_CHECK_IP, headers))['ip']
    typeip = False
    try: 
        socket.inet_pton(socket.AF_INET, ip) 
        typeip ="A"
    except socket.error: 
        try: 
            socket.inet_pton(socket.AF_INET6, ip) 
            typeip ="AAAA"
        except socket.error: 
            typeip = False
    
    return ip, typeip
def get_config(config_path='config.ini'):
    """
    Read and parsing config from ini file.
    Set global var CF_API_TOKEN
    :return:
    """
    global CF_API_TOKEN

    if not path.exists(config_path):
        print("config file not found")
        return False

    config = ConfigParser()
    config.read(config_path)

    if "common" not in config:
        print("Common config not found.")
        return False

    if "CF_API_TOKEN" not in config['common'] or not config['common']['CF_API_TOKEN']:
        print("Missing CloudFlare API Token on config file")
        return False

    CF_API_TOKEN = config['common']['CF_API_TOKEN']

    config_sections = config.sections()
    config_sections.remove("common")

    if not config_sections:
        print("Empty site to update DNS")
        return False

    return config, config_sections
def generate_jwt_token(secret_key: str,payload: dict ):
    keys = payload.keys()
    if "iat" not in keys or "exp" not in keys:
        payload['iat'] =  datetime.datetime.timestamp(datetime.datetime.now())
        payload['exp'] = datetime.datetime.timestamp(datetime.datetime.now() + datetime.timedelta(minutes=15))
    return jwt.encode(payload, secret_key, algorithm='HS256')
def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # doesn't even have to be reachable
        s.connect(('10.255.255.255', 1)) 
        ip = s.getsockname()[0]
    except:
        ip = '127.0.0.1'
    finally:
        s.close()
    try: 
        socket.inet_pton(socket.AF_INET, ip) 
        typeip ="A"
    except socket.error: 
        try: 
            socket.inet_pton(socket.AF_INET6, ip) 
            typeip ="AAAA"
        except socket.error: 
            typeip = False
    
    return ip, typeip
def get_cloudflare_conn(zone):
    cf = False
    try:
        cf = CloudFlare.CloudFlare(token=CLOUDFLARE_TOKEN)
    except CloudFlare.exceptions.CloudFlareAPIError as e:
        print(f'Failed to connect to CloudFlare API ({e})')
        sys.exit(1)

    try:
        if cf:
            zone = get_zone(cf, zone)
        else:
            print('Connection to CloudFlare failed')

    except CloudFlare.exceptions.CloudFlareAPIError as e:
        print(f'Failed to ZoneID ({e})')
    return cf 
def get_zone(conn, zone_name):
    zone_record = False
    try:
        zone_record = conn.zones.get(params={'name': zone_name})[0]
    except CloudFlare.exceptions.CloudFlareAPIError as e:
        print(f'/zones/get {zone_name} - Failed to connect: {e}')
        sys.exit(1)
    except IndexError:
        print(f'Zone {zone_name} was not found on CloudFlare')
        sys.exit(1)

    return zone_record
def check_if_host_exists(cf, zone_id, hostname):
    try:
        params = {'name': hostname, 'match': 'all'}
        dns_record = cf.zones.dns_records.get(zone_id, params=params)[0]
        if len(dns_record) > 0:
            return {
                'status': 'active',
                'record': {
                    'id': dns_record['id'],
                    'content': dns_record['content'],
                    'type': dns_record['type'],
                    'proxiable': dns_record['proxiable'],
                    'proxied': dns_record['proxied'],
                    'ttl': 1,
                    'name': dns_record['name'],
                    'zone_id': dns_record['zone_id'],
                    'zone_name': dns_record['zone_name']
                }}
        else:
            return {'status': 'inactive'}
    except CloudFlare.exceptions.CloudFlareAPIError as e:
        print(f'/zones/dns_records {hostname} - Failed to get hostname: {e}')
        return False
    except IndexError:
        print(f'Record {hostname} was not found!')
        return {'status': 'inactive'}
def record_update(cf, zone_id, dns_name, ip_address, address_type, proxied= True, ttl=1):
    
    record = check_if_host_exists(cf, zone_id, dns_name)
    if record == False: 
        return False
    #print(f'record: {record}')
    is_updated = False
    dns_record = old_ip_address = None
    
    if record['status'] == 'active':

        record = record['record']
        old_ip_address = record['content']
        old_ip_type = record['type']
        old_proxied = record['proxied']

        # Check is a correct entry
        if (address_type and old_ip_type) not in ['A', 'AAAA']:
            print(f'IGNORED: {dns_name} {old_ip_address}; Record type not allowed')
            return False

        ## Check if actual config equal new config
        if ip_address == old_ip_address and old_proxied == proxied:
            print(f'UNCHANGED: {dns_name} {ip_address}')
            is_updated = True
            return True
        
        # Generate payload
        record_data = {
            "name": dns_name,
            "type": address_type,
            "content": ip_address,
            "ttl": ttl,
            "proxied": proxied
        }

        try:
            dns_record = cf.zones.dns_records.put(zone_id, record['id'], data=record_data)
        except CloudFlare.exceptions.CloudFlareAPIError as e:
            print(f'/zones/dns_records {dns_name} - Failed to update hostname: {e}')
            return False
        except IndexError:
            print(f'Record {dns_name} was not found!')
            return False

        print(f'UPDATED: {dns_name} {old_ip_address} -> {ip_address} ; proxied {old_proxied} -> {proxied}')
        is_updated = True
    
    if is_updated:
        return {"status": "updated", "hostname": dns_name, "old_ip": old_ip_address, "new_ip": ip_address}
    
    # Create a new record
    record_data = {"name": f"{dns_name}", "type": address_type, "content": ip_address, "proxied": True}
    if proxied == False:
        record_data = {"name": f"{dns_name}", "type": address_type, "content": ip_address, "proxied": False, "ttl": ttl}
    print(record_data)

    try:
        dns_record = cf.zones.dns_records.post(zone_id, data=json.dumps(record_data))
        
    except CloudFlare.exceptions.CloudFlareAPIError as e:
        print(f'/zones/dns_records {dns_name} - Failed to create hostname: {e}')
        sys.exit(1)

    print(f'CREATED: {dns_name} {ip_address}')
    return {"status": "created", "new_ip": ip_address}
def thread_run():
    keepAlive= True
    while keepAlive:
        print("taking a little breath...")
        time.sleep(2)
        print("running job!")
        run()
        
        if WEEBHOOK is not None:
            print("Running webhook")
            headers = {}
            if JWT_SECRET is not None:
                data = {
                    "func": "cloud_flare_dns_update",
                    "domains": DOMAINS
                }
                jwt_token = generate_jwt_token(JWT_SECRET,data)
                headers['Authorization'] = f"Bearer {jwt_token}"
            if API_KEY is not None:
                headers['x-api-key']= API_KEY

            do_request(WEEBHOOK,headers)
        print("job on idle...")
        if TIME_UPDATE is not  None:
            time.sleep(TIME_UPDATE)
        else:
            keepAlive = False

def run():
    public_ip = get_public_ip()
    local_ip = get_local_ip()
    print(public_ip,local_ip)

    domains = []

    # Extract domains
    global DOMAINS
    DOMAINS = DOMAINS if DOMAINS is not None else ""
    for item in DOMAINS.split("&"):
        if item != "":
            register = (item.split("@"))

            # Check size of register
            if len(register)!= 2:
                print("Check DOMAINS env format incorrect  ex.: domain1@site.com&domain2@site.com")
                sys.exit(1)
            
            # Check options proxy
            proxy = False
            ttl = 1
            domain = register[1]
            if "=" in domain:
                parts = domain.split("=")
                if len(parts)!= 2 or len(parts[1])==0:
                    print("Check DOMAINS env format incorrect  ex.: domain1@site.com=proxy&domain2@site.com=1")
                    sys.exit(1)
                if parts[1]=='proxy':
                    proxy= True
                    domain = parts[0]
                else:
                    try:
                        ttl_type = int(parts[1])
                        ttl = ttl_type
                        domain = parts[0]
                    except: 
                        print("Check DOMAINS env format incorrect  ex.: domain1@site.com=proxy&domain2@site.com=1")
                        sys.exit(1)

            add = {
                "subdomain": register[0],
                "domain": domain,
                "type": public_ip[1],
                "content": public_ip[0],
                "proxy": proxy,
                "ttl": ttl,
                
            }
            domains.append(add)
    
    # Check if option local is active
    if REGISTER_LOCAL is not None:
        
        register = (REGISTER_LOCAL.split("@"))
        if len(register)!= 2:
                print("Check REGISTER_LOCAL env format incorrect  ex.: domain1@site.com")
                sys.exit(1)
        domain = register[1]
        ttl = 1
        # Check if TTL is defined
        if "=" in domain:
            parts = domain.split("=")
            if len(parts)!=2 or len(parts[1])==0:
                print("Check REGISTER_LOCAL env format incorrect  ex.: domain1@site.com==TTL")
                sys.exit(1)
            try:
                ttl_int = int(parts[1])
                ttl = ttl_int
                domain = parts[0]
            except:
                print("Check REGISTER_LOCAL env format incorrect  ex.: domain1@site.com==TTL")
                sys.exit(1)

        add = {
                "subdomain": register[0],
                "domain": domain,
                "type": local_ip[1],
                "content": local_ip[0],
                "proxy": False,
                "ttl": ttl,

            }
        domains.append(add)
    
    # Check for all domains
    last_domain = ""
    conn = False
    record_domain = False
    for item in domains:
        print(item)

        # Reload actual connection
        if last_domain != item['domain']:
            last_domain = item['domain']
            
            conn = get_cloudflare_conn("gingacode.com")
            if conn == False:
                print("Error connecting to CloudFlare")
                sys.exit(1)
            
            record_domain = get_zone(conn,"gingacode.com")
            if record_domain == False:
                print("Error connecting to CloudFlare")
                sys.exit(1)

        if item['proxy'] == True:
            change = record_update(conn,record_domain['id'],f"{item['subdomain']}.{item['domain']}",item['content'],item['type'],True)
            print(change)
        else:
            change = record_update(conn,record_domain['id'],f"{item['subdomain']}.{item['domain']}",item['content'],item['type'],False,item['ttl'])
            print(change)
    return True
    

if __name__ == "__main__":
    
    # Check if env is defined
    if CLOUDFLARE_TOKEN is None:
        print("ENV: You need register CLOUDFLARE_TOKEN to start this application")
        sys.exit(1)
    if DOMAINS is None and REGISTER_LOCAL is None:
        print("ENV: requires at less one type of register DOMAINS or REGISTER_LOCAL")
        sys.exit(1)
    if DOMAINS is not None and URL_CHECK_IP is None:
        print("ENV: If you define DOMAINS registration you need inform the URL_CHECK_IP url")
    
    
    tr = threading.Thread(target=thread_run)
    tr.start()
    tr.join()
    print("Script exit")


