import collections
import sys

from mitmproxy import http
from mitmproxy.net.http.http1.assemble import assemble_request
from bs4 import BeautifulSoup
from mitmproxy import ctx, http
import time
import os
import csv
import random
import typing
from collections import OrderedDict
from getmac import get_mac_address as gma
from mitmproxy.net.http.http1.assemble import _assemble_response_headers, assemble_response
from mitmproxy import flow  # een paar van deze imports doen niets, want MITMdump heeft deze imports niet nodig. Maar, het is wel handig omdat het voor development code completion verbeterd!
from mitmproxy import io
from mitmproxy.exceptions import FlowReadException

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
    # to compare big en small websites there is a small linear increase in small website gram frequency.
    normelizationIncrease = 0.00001
    # config variables:
    blockurls = True
    bannedurls = {
        "pornhub.com": "pornografie"
    }
    uselessinfo = [".js"]
    notintrestingurlparts = ["log_event", "gabo-receiver-service", "net-fortune", "audio", "image", "connect-state",
                             "metadata", "youtubei", "embed"]
    analyseTraffic = False
    logAll = True
    logPath = path
    hardblock = False
    hardblockText = "Website blocked, this behaviour has been logged expect someone to contact you."
    hardblockRetrospect = False
    hardblockSemi = False
    saveWebModus = False
    semiurllog = {"": ""}
    urlOnegrams = {"url": OrderedDict()}
    urlBigrams = {"url": OrderedDict()}
    urlSortedOnegram = {}
    urlSortedBigram = {}
    urlCompareDict = {}

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
        self.loadFilters()
        # Test()



    def loadFilters(self):
        """Laad non intressante url/host parts in. Hiermee kan isUrIntresting() bedenken of we wel naar deze url
        moeten kijken, denk bijv aan urls die images zijn, maar niet eindigen met .png oid. dit zit in een
        txt file, zodat je makkelijk nieuwe dingen kunt toevoegen in de toekomst"""
        path = self.path + "/pathComponentFilterList.txt"
        path2 = self.path + "/fileextentionFilterList.txt"

        with open(path, "r")as textfile:
            for row in textfile:
                if len(row) != 0:
                    row = row.strip()
                    self.notintrestingurlparts.append(row)
        with open(path2, "r")as textfile2:
            for row2 in textfile2:
                if len(row2) != 0:
                    row2 = row2.strip()
                    self.uselessinfo.append(row2)
        ctx.log.info("Filters loaded")

    def loadCompareWebsites(self):
        """Laad verschillende websites in, uit files uit folders waar bepaalde categorieen in zitten"""
        #TODO: Uitbreiden naar elke file in de directory.
        directory = self.path + "/Logs/WebsiteData/"
        "laad alle websites in die gerelateerd zijn aan pornografie"
        self.loadCategoryWebsite("pornografie", directory,)

    def loadCategoryWebsite(Main, category, directory):
        with open(directory + category+".logfile", "rb") as logfile:
            ctx.log.info("reading :"+ directory + category+".logfile")
            freader = io.FlowReader(logfile)
            try:
                for flow in freader.stream():
                    body = str(flow.response.content)
                    url = str(flow.request.pretty_url)
                    # er zit hier een max op omdat sommige URLS erg lang kunen worden.
                    output = Main.filterHtml(Main,body)
                    outputSplit = output.split("\n")
                    Main.analysePrepare(Main,url, outputSplit)
            except FlowReadException as e:
                print("Flow file corrupted: {}".format(e))

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

        ctx.log.info("Banned items loaded.")

    def loadConfig(self):
        """Laad de config file in, lees de config file voor meer informatie over deze variablen.
        ( ja dit zou een kleinbeetje mooier kunnen met een dictionary, als ik tijd over heb ga ik dit zeker doen. )"""
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
                if "SaveWebModus:" in line:
                    if "True" in line:
                        ctx.log.info("Semi hardblocking content")
                        self.saveWebModus = True
                    elif "False" in line:
                        self.saveWebModus = False
        ctx.log.info("Configfile loaded")

    def request(self, flow: http.HTTPFlow) -> None:
        """Deze functie word aangeroepen voor elke http response"""

    # Nu tijdelijk niets wat ik doe met de request.

    def response(self, flow: http.HTTPFlow):
        """Deze functie word aangeroepen voor elke http response, hier roepen we de meeste analyse functies aan
        zoals Analyse, logurl en soort gelijke."""
        # als de status code 200 is en de website dus geladen kan worden.
        alreadyLogged = False
        if flow.response.status_code == 200:
            # als de file geen java script is.( dit zorgt af en toe voor hele lelijke text logging.
            if self.isUrlIntresting(flow):
                if self.analyseTraffic:
                    if not alreadyLogged:
                        self.analyse(flow)
                        alreadyLogged = True

                if self.hardblock:
                    # als url blokkeren doormiddel van blacklists is toegestaan:
                    if any(item in flow.request.pretty_url for item in self.bannedurls.keys()):
                        self.blockWebsite(flow)
                        if not self.alreadyLogged:
                            self.logUrl(flow, self.highrisk)
                            alreadyLogged = True

                elif self.hardblockSemi:
                    if any(item in flow.request.pretty_url for item in self.bannedurls.keys()):
                        if not alreadyLogged:
                            self.blockWebsite(flow)
                            self.logUrl(flow, self.semiriskallowed)
                            alreadyLogged = True

                    elif not alreadyLogged:
                        if any(item in flow.request.pretty_url for item in self.semiurllog.keys()):
                            self.logUrl(flow, self.semirisklog)

                # alles wat in de response zit kan je hier vragen, verwerken en aanpassen
                if self.logAll:
                    self.logUrl(flow)

            alreadyLogged = False

    def isUrlIntresting(self, flow):
        """bekijk de URL data om te kijken of de url wel intressant is om te bekijken."""
        headers = "".join(flow.request.path_components)
        for item in self.uselessinfo:
            if item in headers:
                return False

        for item in self.notintrestingurlparts:
            if item in headers:
                return False
            elif item in flow.request.pretty_url:
                return False

        return True

    def logUrl(self, flow, optional=""):
        """Sla alle urls die een client bezoekt op in een txt file."""
        adress = flow.client_conn.address[0].replace(".", "-")
        adress = adress.replace(":", "-")
        with open(self.path + "/Logs/" + adress + ".txt", "a+") as logfile:
            logfile.write(flow.request.pretty_url + "   at time:" + time.strftime('%X %x %Z') + optional + "\n")

    def saveFlow(self, flow, pathname):
        """Zelf gemaakte functie, die files opslaat op de gegeven path, en weer netjes sluit."""
        f: typing.IO[bytes] = open(pathname, "wb")
        writer = io.FlowWriter(f)
        writer.add(flow)
        f.close()

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

    def analyse(self, flow, loadin=False):
        """een tijdelijke functie die url text data opslaat, later moet dit ook analyseren."""
        if str(flow.request.pretty_url) not in self.uselessinfo:
            ctx.log.info("Analysing: " + flow.request.pretty_url)

            body = flow.response.content
            url = str(flow.request.pretty_url)
            output = self.filterHtml(body)
            outputSplit = output.split("\n")
            self.analysePrepare(url, outputSplit)
            ctx.log.info("NGRAMS WRITTEN...")
            self.compareWebsite(flow)
            ctx.log.info(str(self.urlSortedBigram.keys()))


            ctx.log.info("GRAMS WRITTEN!")
            ctx.log.info(input("Would you like to save the websiteflow of : "+ flow.request.pretty_url))
            if self.saveWebModus:
                    self.saveFlow()

            #directory = "C:/Users/Orang/PycharmProjects/Ipass/Src/Logs/WebsiteData/"
            ##self.saveWebsiteFlow(flow, "pornografie", directory) voorbeeldje van hoe websites op te slaan

    def saveFlow(self,flow):
        category = input("Please give this a category to save to: ")
        directory = "C:/Users/Orang/PycharmProjects/Ipass/Src/Logs/WebsiteData/"
        f: typing.IO[bytes] = open(directory + category + ".logfile" "", "ab")
        flowWriter = io.FlowWriter(f)
        flowWriter.add(flow)
        f.close()
        ctx.log.info("flow saved for website: " + category + ".logfile")

    def analysePrepare(self, url, outputSplit, differentdict=None):
        """"Een kleine versie om een website op teslaan in de dictionaries, zodat we makkelijk websites kunnen inladen
        en her gebruiken later mochten we willen.
        Als je wil dat de dictionaries in een andere dict worden opgeslagen, geef dan de dict mee als differentdict"""
        if differentdict is not None:
            if len(outputSplit) > 0:
                for row in outputSplit:
                    if len(row) >= 2:
                        self.createGrams(Main,row, url)
                self.normalizeGrams(Main,url,self.urlOnegrams[url], self.urlBigrams[url])
        else:
            if len(outputSplit) > 0:
                for row in outputSplit:
                    if len(row) >= 2:
                        self.createGrams(Main,row, url,)
                self.normalizeGrams(Main,url,self.urlOnegrams[url], self.urlBigrams[url])


    def compareWebsite(self, flow):
        """Mijn eigen heuristiek om op een semi-AI manier websites te vergelijken"""
        # TODO: MAKE THIS

    def createGrams(self, row, url,dictone= self.urlOnegrams,dicttwo = self.urlBigrams):
        """"Make and add onegrams to their respective dictionary. Then create bigrams from this onegram.
        These grams are not the traditional gram, but made of words instead of letters."""
        onegramArray = row.split()
        if url not in self.urlOnegrams:
            self.urlOnegrams[url] = {}
        for onegram in range(len(onegramArray)):
            onegramStr = onegramArray[onegram].lower()
            if onegramStr in self.urlOnegrams[url].keys():
                self.urlOnegrams[url][onegramStr] += 1
            else:
                self.urlOnegrams[url][onegramStr] = 1
            # Als de index nog niet de laatste is, maak ook een bigram hiervan.( of als er maar 1 woord is, doe het niet)
            if onegram != len(onegramArray) - 1:
                self.addBiGram(Main,onegramStr + str(onegramArray[onegram + 1]), url)

    def addBiGram(self, concatOneGram, url):
        if url not in self.urlBigrams:
            self.urlBigrams[url] = {}
        if concatOneGram in self.urlBigrams[url].keys():
            self.urlBigrams[url][concatOneGram] = self.urlBigrams[url][concatOneGram] + 1
        else:
            self.urlBigrams[url][concatOneGram] = 1

    def normalizeGrams(self,url, dictone, dicttwo):
        """"count all grams, and normalize the value.( and add a small difference for big webpages!)"""
        dicts = [dictone, dicttwo]
        wordAmount = 0
        for dict in dicts:
            for key in dict.keys():
                wordAmount += dict[key]
            for key in dict.keys():
                amountGram = dict[key]
                if amountGram != 0:
                    dict[key] = amountGram / wordAmount

        self.sortGrams(Main,url, dictone, dicttwo)

    def sortGrams(self,url, dictone, dicttwo):
        if url not in self.urlSortedOnegram:
            self.urlSortedOnegram[url] = {}
        self.urlSortedOnegram[url] = OrderedDict(sorted(dictone.items(), key=lambda t: t[1]))

        if url not in self.urlSortedBigram:
            self.urlSortedBigram[url] = {}
        self.urlSortedBigram[url] = OrderedDict(sorted(dicttwo.items(), key=lambda t: t[1]))

    def filterHtml(self, body):
        """Filter html code from the pure visual text on a website"""
        output = ''
        soup = BeautifulSoup(body, "html.parser")
        for script in soup(["script", "style"]):
            script.extract()
        text = soup.find_all(text=True)
        for t in text:
            if len(t) > 2:
                if t.parent.name not in self.blacklist:
                    output += '{} '.format(t.strip())
        return output


# class Test:
#     """
#     Een classe waar we functies van Main kunnen testen op correcte feedback.
#     """
#
#     def __init__(self):
#         self.testInitial()
#
#     def testInitial(self):
#         """
#         Een uitgebreide functie die meerdere functies test aande hand van het in laden van een test website,
#         en daar functies op te testen. Hiermee testen we dus de save functie, laad functie en ngram creeer functies.
#         """
#         ctx.log.info("testing website load function")
#         directory = Main.path + "/Logs/WebsiteData/"
#         "laad alle websites in die gerelateerd zijn aan pornografie"
#         Main.loadCategoryWebsite(Main,"nieuws", directory)
#         self.testSaveLoad()
#         self.testNgramCreation()
#
#     def testSaveLoad(self):
#         """
#         Simpele functie die gebruik maakt van de load functie van Main.
#         We testen of we de testfile kunnen lezen, en zien de goede url. Dit is een goed genoege indicatie voor
#         een geslaagde load.
#         """
#
#
#         if Main.urlOnegrams.keys[1] == "https://www.nu.nl":
#             #
#             ctx.log.info("test save / load Succes!")
#         else:
#             ctx.log.warn("test save / load Failed...!")
#     def testNgramScan(self):
#         """
#         Simpele functie die gebruik maakt van de create Ngram functies van Main.
#         Op het moment dat de test het woord algemeen kan lezen uit de ngrams, dan kunnen we er vannuit gaan dat
#         deze test ook succesvol is. Aangezien dit ergens boven aan de https gebaseerde website body staat.
#         """
#         if "algemeen" in str(Main.urlOnegrams[Main.urlOnegrams.keys[1]].keys):
#
#             ctx.log.info("test ngram, and dictonary related functions works!")
#         else:
#             ctx.log.warn("test ngram, and dictonary related functions does NOT work...")

addons = [
    Main()
    #,Test()
]
