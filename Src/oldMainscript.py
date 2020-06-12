"""An addon/full program that analyses the risk of visited websites, not compatible with pure MITM proxy."""


dirname, filename = os.path.split(os.path.abspath(__file__))
path = dirname
path = path.replace("\\","/")
macAdress = gma()
initTime = time.strftime('%X %x %Z')
blockurls = True
bannedurls = [
    "pornhub.com"
]
#laad banned url's in:
# with open("bannedurls.csv","rb")as csvfile:
#     csvreader = csv.reader(csvfile,delimiter =",")
#     if
#configfile basis, als er iets fout gaat in de config zijn dit de standaard waarden.
analyseTraffic = False
logAll = True
logPath = path
hardblock = False
hardblockText = "Website blocked, this behaviour has been logged expect someone to contact you."
hardblockRetrospect = False
hardblockSemi = False

#Laad de config file in, lees de config file voor meer informatie over deze variablen. ( ja dit zou een kleinbeetje mooier kunnen met een dictionary, als ik tijd over heb ga ik dit doen. )
with open(path+"/config.txt", "r")as config:
    for line in config:
        if len(line) == 0 or line[0:2] == "//":
            continue
        elif "Analysetraffic:" in line:
            if "True" in line:
                analyseTraffic = True
            elif "False" in line:
                analyseTraffic = False
        elif "LogAll:" in line:
            if "True" in line:
                logAll = True
            elif "False" in line:
                logAll = False
        elif "Path" in line:
            logPath = line.replace("Path:", "")
        elif "HardblockBannedContent:" in line:
            if "True" in line:
                hardblock = True
            elif "False" in line:
                hardblock = False
        elif "HardblockText:" in line:
            if "True" in line:
                hardblockText = True
            elif "False" in line:
                hardblockText = False
        elif "HardblockRetrospect:" in line:
            if "True" in line:
                hardblockRetrospect = True
            elif "False" in line:
                hardblockRetrospect = False
        elif "HardblockSemi:" in line:
            if "True" in line:
                hardblockSemi = True
            elif "False" in line:
                hardblockSemi = False


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
    # Voor elke request word deze functie aangeroepen.
    # als url blokkeren doormiddel van blacklists is toegestaan, en de aangevraagde url deels matched met de banlist:
    if hardblock == True:
        if any(item in flow.request.pretty_url for item in bannedurls):
            flow.response = http.HTTPResponse.make(
                200,  # (optional) status code
                b"<h1>"+hardblockText+"</h1>\n",  # (optional) content
                {"Content-Type": "text/html"}  # (optional) headers
            )


def response(flow: http.HTTPFlow):
    # voor elke http reponse word deze functie aangeroepen.
    # als de status code 200 is en de website dus geladen kan worden.
    if flow.response.status_code == 200:
        #als de file geen java script is.( dit zorgt af en toe voor hele lelijke text logging.
        if ".js" != str(flow.request.pretty_url)[-3:-1]:
            # alles wat in de response zit kan je hier vragen, verwerken en aanpassen
            if logAll == True:
                #Sla alle urls die een client bezoekt op in een txt file.
                adress = flow.client_conn.address[0].replace(".","-")
                adress = adress.replace(":","-")
                with open(path+"/Logs/"+adress+".txt","a+") as logfile:
                    logfile.write(flow.request.pretty_url+"   at time:"+time.strftime('%X %x %Z')+"\n")
            if analyseTraffic == True:
                #een tijdelijke functie die url text data opslaat, later moet dit ook analyseren.
                with open("C:/Users/Orang/PycharmProjects/Ipass/Src/final.txt", "a+")as test:
                    data = assemble_request(flow.request).decode('utf-8')
                    output = ''
                    soup = BeautifulSoup(flow.response.content, "html.parser")
                    #filter text uit de html. Ik wilde dit een losse functie maken, maar dat kan helaas niet door de manier dat mitm is opgebouwd.
                    text = soup.find_all(text=True)
                    for t in text:
                        if t.parent.name not in blacklist:
                            output += '{} '.format(t)
                    test.write(output)
