
from email import header, message
import hashlib
import hmac
import time
import requests
import urllib.parse
import base64
with open("keys.txt","r") as f:
    lines=f.read().splitlines()
    api_key=lines[0]
    api_sec=lines[1]
api_url="https://api.kraken.com"
#get kraken signature
def get_kraken_signature(urlpath,data,secret):
    postdata=urllib.parse.urlencode(data)
    encoded=(str(data['nonce'])+postdata).encode()
    message=urlpath.encode()+hashlib.sha256(encoded).digest()

    mac=hmac.new(base64.b64decode(secret),message,hashlib.sha512)
    sigdigest=base64.b64encode(mac.digest())

    return sigdigest.decode()
def kraken_request(url_path,data,api_key,api_sec):
    headers={'API-Key':api_key,'API-Sign':get_kraken_signature(url_path,data,api_sec)}
    #create the request and get the response
    response=requests.post((api_url+url_path),headers=headers,data=data)
    return response

resp=kraken_request("/0/private/Balance",{
    "nonce":str(int(1000*time.time()))
},api_key,api_sec)
print(resp.json())
