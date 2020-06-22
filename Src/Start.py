import os
import pyfiglet
import colorama
from colorama import Fore, Back, Style
from Main import Main
from tempfile import mkstemp
from shutil import move, copymode
from os import fdopen, remove

"""
Starting-program, Runs the main program, and has an CMD interface to change all editable settings.
"""


class CmdInterface:
    dirname, filename = os.path.split(os.path.abspath(__file__))
    path = dirname
    pathbase = path.replace("Src", "")
    welcome =  pyfiglet.figlet_format("Risk-Sniffer")

    def __init__(self):
        colorama.init()
        self.startGUI()


    def startGUI(self):
        """
      Een mooie UI, om makkelijk opties aan te kunnen passen.
      """

        print(Fore.GREEN + self.welcome)
        print("This is the proxy server startup menu.")
        if self.question("Would you like to run the program with last settings?"):
            self.startprogram()
        else:
            # Fully edit the whole config file.
            self.fullEdit()
            self.startprogram()

    def question(self, question):
        """
      Ask the user a Y/N question, prevents some duplicate code.
      Returns True if the answer is yes.
      Returns False in all other cases.
      """
        yn = input(question + " Y/N: ")
        if yn.replace(" ", "").lower() == "y" or yn.replace(" ", "").lower() == "yes":
            return True
        return False

    def fullEdit(self):
        """
      Rewrite settings askQuestions in logical order. ( some settings make others obsolete and this setup auto fill's
      those settings.)
      I ask these in order: Question(change yes no),
      """
        # Logall
        if self.question(
                "Do you want to log all traffic? This may result in a huge text file with urls."):
            self.editConf("LogAll:", "True")
        else:
            self.editConf("LogAll:", "False")
        # Saveweb modus
        if self.question(
                "Do you want to run the program in saving mode?(to add banned content to a category)" ):
            self.editConf("SaveWebModus:", "True")
        else:
            #Met saveweb modus True hoef je deze instellingen niet te doen.
            self.editConf("SaveWebModus:", "False")
            # Analyse traffic
            if self.question(
                    "Do you want analyse traffic? (needed for most ban and log content functions!)." ):
                self.editConf("Analysetraffic:", "True")
            else:
                self.editConf("Analysetraffic:", "False")
            # HardBlockBannedContent
                if self.question(
                        "Do you want to hard-block all urls in the banned urls list?"):
                    self.editConf("HardBlockBannedContent:", "True")
                else:
                    self.editConf("HardBlockBannedContent:", "False")
                    # SemiBlock
                    if self.question(
                            "Do you want to semi-block all semi block urls in the banned urls list?"):
                        self.editConf("HardblockSemi:", "True")
                    else:
                        self.editConf("HardblockSemi:", "False")
                # HardBlockText
                if self.question(
                        "Do you want to change the text on the url Ban page?"):
                    text = input("What text do you want to display?: ")

                else:
                    self.editConf("HardblockSemi:", "False")
                # HardBlock Retrospect
                    ## Hardblock Semi
            # save website modus
    def editConf(self, settingName, value):
        """
        Edit the Config line for the Main program.
        Simple process, make temp file, copy what needs to be hard copied, and edit wat needs to be editted.
        """
        dirname, filename = os.path.split(os.path.abspath(__file__))
        path = dirname
        file_path = path.replace("\\", "/") + "/config.txt"
        fh, abs_path = mkstemp()
        with fdopen(fh, 'w') as new_file:
            with open(file_path) as old_file:
                for line in old_file:
                    if len(line) == 0 or line[0:2] == "//":
                        new_file.write(line)
                    elif settingName in line:
                        new_file.write(line.replace(line, settingName + value))
                    else:
                        new_file.write(line)
        # Copy the file permissions from the old file to the new file
        copymode(file_path, abs_path)
        # Remove original file
        remove(file_path)
        # Move new file
        move(abs_path, file_path)

    def warn(self, text):
        """
        return text in een rode kleur en reset to groen.
        """
        return Fore.LIGHTRED_EX + text + Fore.GREEN

    def startprogram(self):
        """
        Start the main program!
        """
        start = pyfiglet.figlet_format("Program Running...","drpepper")
        print(start)
        colorama.deinit()
        Main()


addons = [CmdInterface()]
