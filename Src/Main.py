"""An addon/full program that analyses the risk of visited websites, not compatible with pure MITM proxy."""

from mitmproxy import http
from mitmproxy.net.http.http1.assemble import assemble_request
from bs4 import BeautifulSoup
from mitmproxy import ctx, http
import time
import os
from getmac import get_mac_address as gma
from mitmproxy.net.http.http1.assemble import _assemble_response_headers, assemble_response
from mitmproxy import flow
dirname, filename = os.path.split(os.path.abspath(__file__))
path = dirname
macAdress = gma()
initTime = time.strftime('%X %x %Z')
#TODO TOMORROW: IMPORT ALL SETTINGS FROM CONFIG FILE! ( path/config.txt )
blockurls = True
bannedurls = [
    "https://www.pornhub.com/"
]
# list of blocked elements in pure text ( to reduce code in output. )
blacklist = [
    '[document]',
    'noscript',
    'header',
    'html',
    'meta',
    'head',
    'input',
    'script'
]
#

def request(flow: http.HTTPFlow) -> None:
    # alles wat in de persoon zijn request zit kan je hier vragen.

    # als url blocken doormiddel van blacklists is toegestaan, en de aangevraagde url zit in de
    if flow.request.pretty_url in bannedurls and blockurls == True:
        flow.response = http.HTTPResponse.make(
            200,  # (optional) status code
            b"Website blocked, this behaviour has been logged expect your superior to contact you.\n"
            b""
            b"-Ministerie van Defensie",  # (optional) content
            {"Content-Type": "text/html"}  # (optional) headers
        )


def response(flow: http.HTTPFlow):
    # voor elke http reponse word deze functie aangeroepen.
    # als de status code 200 is en de website dus geladen kan worden.
    if flow.response.status_code == 200:
        #als de file geen java script is.
        if ".js" != str(flow.request.pretty_url)[-3:-1]:
            # alles wat in de response zit kan je hier vragen, verwerken en aanpassen
            # voornu sla ik het op in een txt file. TODO: Beter file systeem bedenken, zoals json of csv of iets dergelijks. ( als er tijd over is ook encrypten ivm gevoelige data! )
            with open("C:/Users/Orang/PycharmProjects/Ipass/Src/final.txt", "a+")as test:


                data = assemble_request(flow.request).decode('utf-8')
                output = ''
                soup = BeautifulSoup(flow.response.content, "html.parser")
                #filter html from the text. Sadly I cant make this in a function because of the way MITM is made.
                text = soup.find_all(text=True)
                for t in text:
                    if t.parent.name not in blacklist:
                        output += '{} '.format(t)
                test.write(output)
