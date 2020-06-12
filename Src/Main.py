import collections

from mitmproxy import http
from mitmproxy.net.http.http1.assemble import assemble_request
from bs4 import BeautifulSoup
from mitmproxy import ctx, http
import time
import os
import csv
from getmac import get_mac_address as gma
from mitmproxy.net.http.http1.assemble import _assemble_response_headers, assemble_response
from mitmproxy import \
    flow  # een paar van deze imports doen niets, want MITMdump heeft deze imports niet nodig. Maar, het is wel handig omdat het voor development code completion verbeterd!


class Main:
    """Main program, inhere are all needed information and functions. Functions will most of the times be triggered
    by requests and responses."""
    dirname, filename = os.path.split(os.path.abspath(__file__))
    path = dirname
    path = path.replace("\\", "/")
    macAdress = gma()
    initTime = time.strftime('%X %x %Z')
    highrisk = "\n ^^^^ Highrisk, Direct hardban url detected. ContentBlocked-----------"
    semirisklog = "\n ^^^^ Content allowed, because of semihardblock value."
    semiriskallowed = "\n ^^^^ Semi hardban content blocked, direct hardban -----------"
    #to compare big en small websites there is a small linear increase in small website gram frequency.
    normelizationIncrease = 0.00001
    # config variables:
    blockurls = True
    bannedurls = {
        "pornhub.com": "pornografie"
    }
    uselessinfo = [".js","jpg","png"]

    analyseTraffic = False
    logAll = True
    logPath = path
    hardblock = False
    hardblockText = "Website blocked, this behaviour has been logged expect someone to contact you."
    hardblockRetrospect = False
    hardblockSemi = False
    semiurllog = {"": ""}
    urlOnegrams = {"url": {"onegram": int}}
    urlBigrams = {"url": {"concatOneGram": int}}
    blacklist = [  # these are parts of html that I do not want in pure text.
        '[document]',
        'noscript',
        'header',
        'html',
        'meta',
        'head',
        'input',
        'script'
    ]

    def __init__(self):
        self.num = 0
        self.loadConfig()
        self.loadBannedUrls()

    def loadBannedUrls(self):
        """""Laad alle geblokkeerde urls in, in verhouding met de config instellingen."""
        csvpath = self.path + "/bannedurls.csv"
        with open(csvpath, "r")as csvfile:
            ctx.log.info("opened banned csv")
            csvreader = csv.DictReader(csvfile, delimiter=",")
            if self.hardblock == True:
                for row in csvreader:
                    ctx.log.info("for row in csv hardblock")
                    # als een url in de banned list staat, dan mag deze direct toegevoegd worden, ook zal er een bij behorende category bij zitten.
                    self.bannedurls[row["url"]] = row["category"]
                    ctx.log.info(row["category"])
            elif self.hardblockSemi == True:
                for row in csvreader:
                    if row["semiallowed"] != "True":
                        # als een url niet semi allowed is, voeg het toe aan de banned list.
                        self.bannedurls[row["url"]] = row["category"]
                    elif row["semiallowed"] == "True":
                        self.semiurllog[row["url"]] = row["category"]

        ctx.log.info("all banned urls in list: \n" + str(self.bannedurls.keys()))

    def loadConfig(self):
        """Laad de config file in, lees de config file voor meer informatie over deze variablen. ( ja dit zou een kleinbeetje mooier kunnen met een dictionary, als ik tijd over heb ga ik dit zeker doen. )"""
        with open(self.path + "/config.txt", "r")as config:
            for line in config:
                if len(line) == 0 or line[0:2] == "//":
                    continue
                if "Analysetraffic:" in line:
                    if "True" in line:
                        self.analyseTraffic = True
                        ctx.log.info("Analysing Traffic")
                    elif "False" in line:
                        self.analyseTraffic = False
                if "LogAll:" in line:
                    if "True" in line:
                        self.logAll = True
                        ctx.log.info("Logging all Traffic")
                    elif "False" in line:
                        self.logAll = False
                if "Path" in line:
                    self.logPath = line.replace("Path:", "")
                if "HardBlockBannedContent:" in line:
                    if "True" in line:
                        ctx.log.info("Hardblocking banned Traffic")
                        self.hardblock = True
                    elif "False" in line:
                        ctx.log.info("Not Hardblocking banned Traffic")
                        self.hardblock = False
                if "HardBlockText:" in line:
                    if "True" in line:
                        self.hardblockText = True
                    elif "False" in line:
                        self.hardblockText = False
                if "HardblockRetrospect:" in line:
                    if "True" in line:
                        ctx.log.info("Analysing Traffic, and retrospectively blocking content")
                        self.hardblockRetrospect = True
                    elif "False" in line:
                        self.hardblockRetrospect = False
                if "HardblockSemi:" in line:
                    if "True" in line:
                        ctx.log.info("Semi hardblocking content")
                        self.hardblockSemi = True
                    elif "False" in line:
                        self.hardblockSemi = False

    def request(self, flow: http.HTTPFlow) -> None:
        """Deze functie word aangeroepen voor elke http response"""

    # Nu tijdelijk niets wat ik doe met de request.

    def response(self, flow: http.HTTPFlow):
        """Deze functie word aangeroepen voor elke http response"""
        # als de status code 200 is en de website dus geladen kan worden.
        alreadyLogged = False
        if flow.response.status_code == 200:
            # als de file geen java script is.( dit zorgt af en toe voor hele lelijke text logging.
            if str(flow.request.pretty_url)[-3:-1] not in self.uselessinfo:
                if self.analyseTraffic == True:
                    if alreadyLogged != True:
                        self.analyse(flow)
                        alreadyLogged = True

                if self.hardblock == True:
                    # als url blokkeren doormiddel van blacklists is toegestaan:
                    if any(item in flow.request.pretty_url for item in self.bannedurls.keys()):
                        self.blockWebsite(flow)
                        if not self.alreadyLogged:
                            self.logUrl(flow, self.highrisk)
                            alreadyLogged = True

                elif self.hardblockSemi == True:
                    if any(item in flow.request.pretty_url for item in self.bannedurls.keys()):
                        if alreadyLogged != True:
                            self.blockWebsite(flow)
                            self.logUrl(flow, self.semiriskallowed)
                            alreadyLogged = True
                    elif alreadyLogged != True:
                        if any(item in flow.request.pretty_url for item in self.semiurllog.keys()):
                            self.logUrl(flow, self.semirisklog)

                # alles wat in de response zit kan je hier vragen, verwerken en aanpassen
                if self.logAll == True:
                    self.logUrl(flow)

            alreadyLogged = False

    def logUrl(self, flow, optional=""):
        """Sla alle urls die een client bezoekt op in een txt file."""
        adress = flow.client_conn.address[0].replace(".", "-")
        adress = adress.replace(":", "-")
        with open(self.path + "/Logs/" + adress + ".txt", "a+") as logfile:
            logfile.write(flow.request.pretty_url + "   at time:" + time.strftime('%X %x %Z') + optional + "\n")

    def blockWebsite(self, flow):
        """Manier om een website te blokeren, door de response een andere website te maken. Hierdoor kunnen we de response nog wel lezen,
         en zou de payload van een security risk nogsteeds binnen in ons systeem kunnen komen.
         Door dit soort design keuzens is deze software meer gebaseert op user control, dan daadwerkelijke virus preventie."""
        flow.response = http.HTTPResponse.make(
            200,  # (optional) status code
            b"<h1> blocked website by Ministerie van Defensie this activity has been logged.</h1>\n",
            # (optional) content
            {"Content-Type": "text/html"}  # (optional) headers

        )

    def analyse(self, flow):
        """een tijdelijke functie die url text data opslaat, later moet dit ook analyseren."""
        with open("C:/Users/Orang/PycharmProjects/Ipass/Src/grams.txt", "a+")as test:
            body = flow.response.content
            url = str(flow.request.pretty_url[0:79])
            output = self.filterHtml(body)
            for row in output:
                if len(row) >= 2:
                    self.createGrams(row, url)
                    self.normalizeGrams(self.urlOnegrams[url],self.urlBigrams[url])


            ##TODO:if website is seen as a risk, write the website text as file. And log activity etc.
            ctx.log.info("GRAMS WRITING...."+ str(type(self.urlOnegrams)) )
            onekeyvaluestring = ""
            for key, value in self.urlOnegrams[url].items():
                ctx.log.info(str(key) + str(value))
                onekeyvaluestring =onekeyvaluestring + str(key) + str(value)
            bikeyvaluestring = ""
            for key, value in self.urlBigrams[url].items():
                bikeyvaluestring = bikeyvaluestring + str(key) + str(value)
            test.write("url: "+url+"\n"+onekeyvaluestring+"and bigrams:"+bikeyvaluestring+"\n")
            ctx.log.info("GRAMS WRITTEN!")
            ##TODO:if website is not seen as a risk, move to array of "safe websites"


    def createGrams(self, row, url):
        """"Make and add onegrams to their respective dictionary. Then create bigrams from this onegram.
        These grams are not the traditional gram, but made of words instead of letters."""
        onegramArray = row.split()
        for onegram in len(onegramArray):
            onegramStr = str(onegramArray[onegram])
            self.urlOnegrams[url] = {onegramStr: +1}
            #Als de index nog niet de laatste is, maak ook een bigram hiervan.( of als er maar 1 woord is, doe het niet)
            if onegram != len(onegramArray):
                self.addBiGram(onegramStr+str(onegramArray[onegram+1]),url)

    def addBiGram(self,concatOneGram,url):
        self.urlBigrams[url] = {concatOneGram: +1}

    def normalizeGrams(self,dictone,dicttwo):
        """"count all grams, and normalize the value.( and add a small difference for big webpages!)"""
        dicts = [dictone,dicttwo]
        for dict in dicts:
            wordAmount: 0
            for key in dict.keys():
                wordAmount += dict[key]

            for key in dict.keys():
                amountGram = dict[key]
                if amountGram != 0:
                    dict[key] = amountGram/(wordAmount+wordAmount*self.normelizationIncrease)


    def filterHtml(self, body):
        """Filter html code from the pure visual text on a website"""
        output = ''
        soup = BeautifulSoup(body, "html.parser")
        text = soup.find_all(text=True)
        for t in text:
            if t.parent.name not in self.blacklist:
                output += '{} '.format(t)
        return output


addons = [
    Main()
]
