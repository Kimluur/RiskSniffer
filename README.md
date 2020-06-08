# RiskSniffer ( work in progress )
 A http(s) Sniffer in python that tries to determine risks by textmining/analysis algorithms 
 All my code is written in Src. Almost all comments are in Dutch, because the company that gave me this assignment is dutch.
 
 This project uses MITM proxy as a framework: https://github.com/mitmproxy/mitmproxy 
 
 This is NOT an attack framework, because you will need root and admin access to all computers on the network, meaning that this can only be used and should only be used if you are fully authorised to see ALL internet traffic on these computers. Please keep the European General Data Protection Regulation (AVG) in mind when using this software.
 
 ##### A warning in advance:
 This program decrypts all traffic, by creating an SSL certificate, and manually adding it to the trusted certificates list.
 Because of this, I would recommend to NOT share the certificate with other people that have or might have access to your network. This will mean that they will be able to see all traffic including passwords, usernames and other sensitive information.
 This program could also be modified to edit the webpages users see, what can give an attacker in your network a whole new framework for phishing/ credential-stealing. Please, notify your users to not enter ANY personal information on the computers that you installed this proxy sniffer, because these could be stolen. 
 
 Also, this program is made for a small branche of the Armed forces of the Netherlands. Meaning that any use of this program without  their authorisation will be seen as stealing 

 
##How to install

install the certs in the browsers, and windows of the hosts you want to sniff/analyse. ( from C:\Users\"your host/user here"\.mitmproxy by default) (Will showup after running the mitmdump command once.) 

configure the config file in de /src folder for your use case.

There is a windows installer in commandline(certutil), but for example Firefox I could not figure out how to auto install the selfmade cert. 

To be able to run this project, you need to add the DEV version of MITM-proxy to this folder with the standard name: mitmproxy

## There are going to be 2 modes this proxy sniffer might be utilized: 

### 1. Local use, with external path setup
Install this full program on a desktop that you want to monitor, and make the path to save the log's on a shared folder on the network. ( no central server needed, and faster analysis since everycomputer analyses their own traffic.) ( fast but less secure.)

### 2. External proxy, with 1 central proxy server
Install this full program on a desktop/server computer with alot/decent amount of proccessing power. 
Install a proxy redirect on all desktops towards this pc's IP-Adress + port 8080. 
( program will not be edittable from the other pc's + chance of this program being detected(and abused) by the user is a-lot lower, But the internet traffic might be a bit slower, since all traffic is re routed to one pc and then being analysed on the same desktop. )( Secure but slower internet speeds(if the central server does not have enough ram.) )

To run this program without the Startup.py(todo: make startup.py) enter following commands:

		cd "yourpathhere"\mitmproxy
		
		venv\Scripts\activate
		
		mitmdump -s C:\Users\Orang\PycharmProjects\Ipass\Src\Main.py -q (for local server on port 8080)
		
		mitmdump -s C:\Users\Orang\PycharmProjects\Ipass\Src\Main.py -q --listen-host "host ip here" (for externalproxy support)
		
Check mitmdump --help for more intresting options! ( some might break the program, be warned!)

