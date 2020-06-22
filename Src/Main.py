import collections
import statistics
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
from mitmproxy import flow
# een paar van deze imports doen niets, want MITMdump heeft deze imports niet nodig.
# Maar, het is wel handig omdat het voor development code completion verbeterd!
from mitmproxy import io
from mitmproxy.exceptions import FlowReadException


class Main:
    """
    Main program, inhere are all needed information and functions. Functions will most of the times be triggered
    by http(s)flow responses.
    Deze applicatie word in zijn geheeld door Cython gepiped door MITM-Dump( hierdoor is het nog sneller dan normaal)
    """
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
    urlCatagoryPercent = {}
    whitelist = []
    catagoryTrigger = {"catagory": 10}
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
        """Load all the things!"""
        self.loadConfig()
        self.loadBannedUrls()
        self.loadFilters()
        self.loadCompareWebsites()
        ctx.log.info("Main program successfully initialized and starting now.")

    def loadFilters(self):
        """
        Laad non intressante url/host parts in. Hiermee kan isUrIntresting() bedenken of we wel naar deze url
        moeten kijken, denk bijv aan urls die images zijn, maar niet eindigen met .png oid. dit zit in een
        txt file, zodat je makkelijk nieuwe dingen kunt toevoegen in de toekomst
        """
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
        """
        Laad verschillende websites in, uit files uit folders waar bepaalde categorieen in zitten.
        Om meer categorieën toe te voegen, hoef je alleen de loadCategoryWebsite() te gebruiken.
        Geef daar aan mee de string naam van je category, waarvan ook al een file save zou moeten zijn.
        (deze kan je makenmet de save modus!)
        """
        directory = self.path + "/Logs/WebsiteData/"

        # laad websites in die gerelateerd zijn aan pornografie, zodat we andere soort gelijke websites kunnen vergelijken
        self.loadCategoryWebsite("pornografie", directory, 2.6)
        ctx.log.info("All compare based categories have been loaded.")

    def loadWhitelist(self):
        """
        Function that loads the whitelist. Whitelist specific urls only! you can whitelist https://wikipedia.org
        but https://en.wikipedia.org/wiki/Pornography might still be blocked.

        Sometimes the program sees something as a high risk, but you might not see this as a risk.
        If this is the case, please evaluate the website carefully and if you deem is safe to visit, add it to the whitelist
        For example: Wikipedia has pages related to pornografic material. But because it does not contains porn,
        I personally would not deem this webpage to be a policy risk. This is the first and only added entry to the
        whitelist. If you want you could add more, or clean the whitelist completely.
        """
        try:
            directory = self.path + "/whitelistedurls.txt"
            with open(directory, "r") as whitelist:
                for line in whitelist:
                    self.whitelist.append(line)
        except:
            ctx.log.error("Whitelist cant be found or cant be loaded.")

    def loadCategoryWebsite(self, category, directory, blockpercentage):
        """
        Laad een category aan websites in, in een dict voor die category.
        Werkt alleen voor standaard categorieeën. Dit is helaas niet scaleable, omdat ik niet weet hoe ik
        variablen namen geef zonder dat ik op voorhand de naam ken.
        """
        with open(directory + category + ".logfile", "rb") as logfile:
            freader = io.FlowReader(logfile)
            try:
                for flow in freader.stream():

                    body = str(flow.response.content)
                    url = str(flow.request.pretty_url)

                    # er zit hier een max op omdat sommige URLS erg lang kunen worden.
                    output = self.filterHtml(body)
                    outputLines = output.split("\n")
                    if category not in self.urlCompareDict.keys():
                        self.urlCompareDict[category] = {}
                    if url not in self.urlCompareDict[category].keys():
                        self.urlCompareDict[category][url] = {}

                    self.analysePrepare(url, outputLines, self.urlCompareDict[category][url])

            except FlowReadException as e:
                print("Flow file corrupted: {}".format(e))

    def loadBannedUrls(self):
        """
        Laad alle geblokkeerde urls in, in verhouding met de config instellingen.
        """
        csvpath = self.path + "/bannedurls.csv"
        with open(csvpath, "r")as csvfile:
            csvreader = csv.DictReader(csvfile, delimiter=",")
            if self.hardblock == True:
                for row in csvreader:
                    ctx.log.info("for row in csv hardblock")
                    # als een url in de banned list staat, dan mag deze direct toegevoegd worden, ook zal er een bij
                    # behorende category bij zitten.
                    self.bannedurls[row["url"]] = row["category"]
                    ctx.log.info(row["category"])
            elif self.hardblockSemi == True:
                for row in csvreader:
                    if row["semiallowed"] != "True":
                        # als een url niet semi allowed is, voeg het toe aan de banned list.
                        self.bannedurls[row["url"]] = row["category"]
                    elif row["semiallowed"] == "True":
                        self.semiurllog[row["url"]] = row["category"]

        ctx.log.info("Banned websites-list loaded.")

    def loadConfig(self):
        """
        Laad de config file in, lees de config file voor meer informatie over deze variablen.
        ( ja dit zou een kleinbeetje mooier kunnen met een dictionary, als ik tijd over heb ga ik dit zeker doen. )
        """
        with open(self.path + "/config.txt", "r")as config:
            ctx.log.info("--------------------------------------")
            ctx.log.info("All following info are Config setting:")
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
        ctx.log.info("--------------------------------------")

    def request(self, flow: http.HTTPFlow) -> None:
        """
        Deze functie word aangeroepen voor elke http response
        """

    # Nu tijdelijk niets wat ik doe met de request, nog geen noodzaak voor gehad. Ik zou al eerder kunnen controleren
    # op websites die verdacht zijn, maar als de client met een proxy of redirect naar een banned server gaat zou je
    # dit niet op vangen. Vandaar dat ik alles vannuit de responses op heb gebouwd

    def response(self, flow: http.HTTPFlow):
        """
        Deze functie word aangeroepen voor elke http response, hier roepen we de meeste analyse functies aan
        zoals Analyse, logurl en soort gelijke. Dit is de "starting block" van bijna al mijn functies.
        """
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
                        if not alreadyLogged:
                            self.logUrl(flow, self.highrisk)
                            alreadyLogged = True

                elif self.hardblockSemi:
                    if any(item in flow.request.pretty_url for item in self.bannedurls.keys()):
                        self.blockWebsite(flow)
                        if not alreadyLogged:
                            self.logUrl(flow, self.semiriskallowed)
                            alreadyLogged = True

                    if any(item in flow.request.pretty_url for item in self.semiurllog.keys()):
                        if not alreadyLogged:
                            self.logUrl(flow, self.semirisklog)

                # alles wat in de response zit kan je hier vragen, verwerken en aanpassen
                if self.logAll:
                    self.logUrl(flow)

            alreadyLogged = False

    def isUrlIntresting(self, flow):
        """
        bekijk de URL data om te kijken of de rest van de data wel intressant is om te bekijken.
        """
        headers = "".join(flow.request.path_components)
        for item in self.uselessinfo:
            if item in headers:
                return False

        for url in self.bannedurls:
            # als de url al gebanned is, hoeven we deze niet nog een keer te controleren!
            if url in headers:
                self.logUrl(flow)
                self.blockWebsite(flow)
                return False

        for item in self.notintrestingurlparts:
            if item in headers:
                return False
            elif item in flow.request.pretty_url:
                return False

        return True

    def logUrl(self, flow, optional=""):
        """
        Sla alle urls die een client bezoekt op in een txt file.
        """
        adress = flow.client_conn.address[0].replace(".", "-")
        adress = adress.replace(":", "-")
        with open(self.path + "/Logs/" + adress + ".txt", "a+") as logfile:
            logfile.write(flow.request.pretty_url + "   at time:" + time.strftime('%X %x %Z') + optional + "\n")

    def saveFlow(self, flow, pathname):
        """
        Zelf gemaakte functie, die files opslaat op de gegeven path, en weer netjes sluit.
        """
        f: typing.IO[bytes] = open(pathname, "wb")
        writer = io.FlowWriter(f)
        writer.add(flow)
        f.close()

    def blockWebsite(self, flow):
        """
        Manier om een website te blokeren, door de response een andere website te maken. Hierdoor kunnen we de response nog wel lezen,
        en zou de payload van een security risk nogsteeds binnen in ons systeem kunnen komen.
        Door dit soort design keuzens is deze software meer gebaseert op user control, dan daadwerkelijke virus preventie.
        """
        flow.response = http.HTTPResponse.make(
            200,  # (optional) status code
            b"<h1> blocked website by Ministerie van Defensie this activity has been logged.</h1>\n",
            # (optional) content
            {"Content-Type": "text/html"}  # (optional) headers

        )

    def analyse(self, flow, loadin=False):
        """
        Functie voert het uitvoeren van een nieuwe flow uit. Deze volgorde kan NIET als de flow al een keer geanalysed.
        """
        if str(flow.request.pretty_url) not in self.uselessinfo:
            if str(flow.request.pretty_url) not in self.whitelist:
                ctx.log.info("Analysing: " + flow.request.pretty_url)

                body = flow.response.content
                url = str(flow.request.pretty_url)
                # Als de url is geanalyseerd hoeft dit niet nog een keer te gebeuren.
                if str(url) in str(self.urlSortedBigram.keys()):
                    if url in self.urlCatagoryPercent.keys():
                        ctx.log.info("Url already analysed. No need to analyse again.")
                else:
                    output = self.filterHtml(body)
                    outputSplit = output.split("\n")
                    self.analysePrepare(url, outputSplit)
                    self.compareWebsite(url, flow)

                    if not loadin:
                        if self.saveWebModus:
                            yn = input(
                                "Would you like to save the flow of this url? : " + flow.request.pretty_url + " Y / N : ")
                            if yn.lower() == "y":
                                self.saveFlow(flow)
                                ctx.log.info("flowSaved")

                ##self.saveWebsiteFlow(flow, "pornografie", directory) voorbeeldje van hoe websites op te slaan

    def saveFlow(self, flow):
        """
        Save a given flow in the given category. You can use this function to add data to the compareative dataset.
        """
        category = input("Please give this a category to save to: ")
        directory = self.path + "/Logs/WebsiteData/"
        f: typing.IO[bytes] = open(directory + category + ".logfile" "", "ab")
        flowWriter = io.FlowWriter(f)
        flowWriter.add(flow)
        f.close()
        ctx.log.info("flow saved for category: " + category + ".logfile")

    def analysePrepare(self, url, outputSplit, differentdict=None):
        """
        Een kleine versie om een website op teslaan in de dictionaries, zodat we makkelijk websites kunnen inladen
        en her gebruiken later mochten we willen.
        Als je wil dat de dictionaries in een andere dict worden opgeslagen, geef dan de dict mee als differentdict
        """
        if differentdict is not None:
            if len(outputSplit) > 0:
                for row in outputSplit:
                    if len(row) >= 2:
                        if "onegram" not in differentdict.keys():
                            differentdict["onegram"] = {}
                            differentdict["onegram"][url] = {}
                        if "bigram" not in differentdict.keys():
                            differentdict["bigram"] = {}
                            differentdict["bigram"][url] = {}
                        self.createGrams(row, url, differentdict["onegram"][url], differentdict["bigram"][url], True)
                        # Doel final gram : urlcomp= {category:{url:{amountgram:{gram:countofthisgram in website}}}}
                self.normalizeGrams(url, differentdict["onegram"], differentdict["bigram"])
        else:

            if len(outputSplit) > 0:
                for row in outputSplit:
                    if len(row) >= 2:
                        self.createGrams(row, url, self.urlOnegrams, self.urlBigrams)

                self.normalizeGrams(url, self.urlOnegrams, self.urlBigrams, )

    def compareWebsite(self, url, flow):
        """
        Mijn eigen heuristiek om op een semi-AI manier websites te vergelijken
        Uitleg:
        We loopen door onze data set heen, per categorie. En vergelijken we de percentages van hoeveel elke set woorden
        (bigram) voorkomt per website.
        De percentage overeenkomst per bigram tellen wij dan op, en nemen we hier de mediaan van.

        EXTRA TOELICHTING IN DE DOCS!
        TODO: Docs maken met extra toelichting
        Officieel zijn Ngram's sets aan letters, maar dit neemt  meer tijd in beslag om allemaal op te slaan,
        en als ik woorden gebruik, is de kans op semantiek meenemen ook groter. Ik ben door middel van testen er achter
        gekomen dat 2 woorden het meest effectief is, zonder dat het té specifiek is om triggers tegen te komen.
        ( Met grotere data sets zou dit wellicht verhoogt kunnen worden. Maar dit werkt al vrij stabiel met een kleine
        data set.)
        Ik heb ook bekeken of een gemiddelde niet beter zou zijn, maar dan krijg je meer false positives, doordat
        hij misschien enorm lijkt op 1 website in de data set door woorden zoals "the, and, it". Hierdoor had mijn
        algoritme een 34% overeenkomst met de "English language wikipeda" en alle porno websites in mijn standaard dataset.
        Door de mediaan te gebruiken is het veel stabieler geworden.
        De uitgebreider de data set, de beter de algoritmes zullen worden. Mocht er in de toekomst nog tijd zijn, ga
        ik dit project zeker nog uitwerken met online-learning waardoor hij nieuwe websites, ook aan de respectievelijke
        datasets kan toevoegen. Maar dit is helaas niet mogenlijk zonder AI. Hierdoor heb ik dit in deze ( stabiel werkende)
        website er uit gelaten.
        """
        if str(url) in str(self.urlSortedBigram.keys()):
            if url in self.urlCatagoryPercent.keys():
                # Url has already been checked, but maby we want to double check?
                ctx.log.warn("url already been checked. no second analysis needed.")
                ctx.log.info(str(self.urlCatagoryPercent[url].keys()))
                for category in self.urlCatagoryPercent[url].keys():
                    if self.urlCatagoryPercent[url][category] * 100 > self.catagoryTrigger[category]:
                        self.logUrl(flow, self.highrisk)
                        if self.hardblockRetrospect:
                            self.blockWebsite(flow)
            else:
                percSimilar = 0
                dictionary = self.urlSortedBigram[url]
                compare = self.urlCompareDict
                keywords = {}
                for categorie in compare:
                    amountwebsites = 0
                    websitepercentages = []
                    for website in compare[categorie]:
                        amountwebsites += 1
                        if url not in self.urlCatagoryPercent:
                            self.urlCatagoryPercent[url] = {}
                        for gram in compare[categorie][website]["bigram"][website]:
                            if gram in self.urlSortedBigram[url].keys():
                                percSimilar += abs(
                                    dictionary[gram] - compare[categorie][website]["bigram"][website][gram])
                                if categorie in keywords.keys():
                                    keywords[categorie] = keywords[categorie] + gram
                                else:
                                    keywords[categorie] = gram

                        websitepercentages.append(percSimilar)
                    # Voor elke website bereken de percentage mediaan, dit werkt stabieler dan gemiddelden.
                    self.urlCatagoryPercent[url][categorie] = statistics.median(websitepercentages)
                    ctx.log.info(str((self.urlCatagoryPercent[url][categorie]) * 100) + " percent compare with porn")
                    if self.urlCatagoryPercent[url][categorie] * 100 > 2:
                        self.logUrl(flow, self.highrisk + (" for the keywords: " + keywords[categorie]))
                        if self.hardblockRetrospect:
                            self.blockWebsite(flow)
                            ctx.log.info("website blocked")
                        else:
                            ctx.log.warn("hardblock retrospect not on, so program wont block. only log.")


        else:
            ctx.log.warn("Url can be analysed, but not compared because something went wrong in the creation of dicts.")

    def createGrams(self, row, url, dictone, dicttwo, urlalreadygiven=False):
        """"Make and add onegrams to their respective dictionary. Then create bigrams from this onegram.
        These grams are not the traditional gram, but made of words instead of letters."""
        if urlalreadygiven:
            onegramArray = row.split()
            for onegram in range(len(onegramArray)):
                onegramStr = onegramArray[onegram].lower()
                if onegramStr in dictone.keys():

                    dictone[onegramStr] += 1
                else:
                    dictone[onegramStr] = 1
                # Als de index nog niet de laatste is, maak ook een bigram hiervan.( of als er maar 1 woord is, doe het niet)
                if onegram != len(onegramArray) - 1:
                    self.addBiGram(onegramStr + str(onegramArray[onegram + 1]), url, dicttwo)
        else:

            onegramArray = row.split()
            if url not in dictone:
                self.urlOnegrams[url] = {}
            for onegram in range(len(onegramArray)):
                onegramStr = onegramArray[onegram].lower()
                if onegramStr in self.urlOnegrams[url].keys():
                    self.urlOnegrams[url][onegramStr] += 1
                else:
                    self.urlOnegrams[url][onegramStr] = 1
                # Als de index nog niet de laatste is, maak ook een bigram hiervan.( of als er maar 1 woord is, doe het niet)
                if onegram != len(onegramArray) - 1:
                    self.addBiGram(onegramStr + str(onegramArray[onegram + 1]), url)

    def addBiGram(self, concatOneGram, url, urlalreadygiven=False):
        """"
        Maak Bigrams van de gegeven onegram, en zet het in een dictionary.
        """
        if urlalreadygiven is not False:
            if concatOneGram in urlalreadygiven.keys():
                urlalreadygiven[concatOneGram] = urlalreadygiven[concatOneGram] + 1
            else:
                urlalreadygiven[concatOneGram] = 1
        else:
            if url not in self.urlBigrams:
                self.urlBigrams[url] = {}
            if concatOneGram in self.urlBigrams[url].keys():
                self.urlBigrams[url][concatOneGram] = self.urlBigrams[url][concatOneGram] + 1
            else:
                self.urlBigrams[url][concatOneGram] = 1

    def normalizeGrams(self, url, dictone, dicttwo):
        """
        count all grams, and normalize the value. ( percentage / 100)
        """
        dicts = [dictone, dicttwo]
        wordAmount = 0
        for dict in dicts:
            # if key not in dict.keys():
            #
            for key in dict[url].keys():
                wordAmount += dict[url][key]
            for key in dict[url].keys():
                amountGram = dict[url][key]
                if amountGram != 0:
                    dict[url][key] = amountGram / wordAmount

        self.sortGrams(url, dictone, dicttwo)

    def sortGrams(self, url, dictone, dicttwo):
        """"
        Put 2 grams in the correct order for values. In a ordered dict.
        """

        self.urlSortedOnegram[url] = OrderedDict(sorted(dictone[url].items(), key=lambda t: t[1]))

        if url not in self.urlSortedBigram:
            self.urlSortedBigram[url] = {}

        self.urlSortedBigram[url] = OrderedDict(sorted(dicttwo[url].items(), key=lambda t: t[1]))

    def filterHtml(self, body):
        """
        Filter html code from the pure visual text on a website
        """
        output = ''
        soup = BeautifulSoup(body, "html.parser")
        for script in soup(["script", "style"]):
            script.extract()
        text = soup.find_all(text=True)
        for t in text:
            if t == "\\n":
                continue
            if len(t) > 2:
                # als er nog blacklisted elements in zitten, haal ze eruit.
                if t.parent.name not in self.blacklist:
                    output += '{} '.format(t.strip())
                try:
                    t = t.replace("\\n", "")
                    t = t.replace("\\t", "")
                except:
                    ctx.log.error("stripping failed")

        return output
