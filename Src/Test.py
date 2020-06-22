from mitmproxy import ctx
from Main import Main
from Start import CmdInterface

class Test:
    """
    Een classe waar we functies van Main kunnen testen op correcte feedback.
    Run door middel van standaard opstart MITMDump maar dan met test.py ipv start.py!
    Helaas is het algoritme niet met deze functie te testen, dit heb ik met de hand moeten doen.
    Verdere toelichting hierover in mijn DOCS!
    """
    m = Main()
    cmd = CmdInterface()
    def __init__(self):
        self.testInitial()

    def testInitial(self):
        """
        Een uitgebreide functie die meerdere functies test aande hand van het in laden van een test website,
        en daar functies op te testen. Hiermee testen we dus de save functie, laad functie en ngram creeer functies.
        """
        # try:

        directory = self.m.path + "/Logs/WebsiteData/"
        "laad alle websites in die gerelateerd zijn aan pornografie"
        self.m.loadCategoryWebsite("nieuws", directory)

        self.testSaveLoad()

        self.testNgramCreation()

        # All tests finished, exiting program.
        exit()

    def testSaveLoad(self):
        """
        Simpele functie die gebruik maakt van de load functie van Main.
        We testen of we de testfile kunnen lezen, en zien de goede url. Dit is een goed genoege indicatie voor
        een geslaagde load.
        """

        if "nieuws" in self.m.urlCompareDict.keys():
            #
            ctx.log.info("test save / load Succes!")
        else:
            ctx.log.warn("test save / load Failed...!")

    def testNgramCreation(self):
        """
        Simpele functie die gebruik maakt van de create Ngram functies van Main.
        Op het moment dat de test het woord algemeen kan lezen uit de ngrams, dan kunnen we er vannuit gaan dat
        deze test ook succesvol is. Aangezien dit ergens boven aan de https gebaseerde website body staat.
        """

        if "algemeen" in str(self.m.urlCompareDict["nieuws"]["onegram"].keys()):
            # compare[categorie][website]["bigram"][website]
            ctx.log.info("test ngram, and dictonary related functions works!")
        else:
            ctx.log.warn("test ngram, and dictonary related functions does NOT work...")


addons = [Test()]
