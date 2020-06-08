# RiskSniffer
 A http(s) Sniffer in python that tries to determine risks by textmining/analysis algorithms 
 
All my code is written in Src. Almost all comments are in Dutch, because the company that gave me this assignment is dutch.
 
 This project uses MITM proxy as a framework: https://github.com/mitmproxy/mitmproxy 

 To be able to run this project, you need to add the DEV version of MITM-proxy to this folder with the standard name: mitmproxy
	also dont forget to venv\Scripts\activate in your ide, if you want to test your mitm proxy.
	
	Rightnow the program is a work in progress, but later you will be able to run the main file in src, what will run the whole program

Dont forget to install the certs in the browsers, and windows. 
There is a windows installer in commandline(certutil), but for example Firefox I could not figure out how to auto install the selfmade cert. 

There are going to be 2 modes this proxy sniffer might work: 

1. Install this full program on a desktop that you want to monitor, and make the path to save the log's a shared folder on the network. ( no central server needed, and faster analysis since everycomputer analyses their own traffic.) ( fast but less secure.)

2. Install this full program on a desktop/server computer with alot/decent amount of proccessing power. 
Install a proxy redirect on all desktops towards this pc's IP-Adress + port 8080. 
( program will not be edittable from the other pc's + chance of this program being detected(and abused) by the user is a-lot lower, But the internet traffic might be a bit slower, since all traffic is re routed to one pc and then being analysed on the same desktop. )( Secure but slower internet speeds(if the central server does not have enough ram.) )
