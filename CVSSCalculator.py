#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Author: n0t4u
# Version: 0.2.1

# Imports
import argparse
import logging
from termcolor import colored
import math
import matplotlib.pyplot as plt
import re
import sys
#from threading import Lock


# Classes
class CVSSVector:
    scores = {"AV:N": 0.85,
              "AV:A": 0.62,
              "AV:L": 0.55,
              "AV:P": 0.2,
              "AC:L": 0.77,
              "AC:H": 0.44,
              "PR:N": 0.85,
              "PR:LC": 0.68,  # low and changed
              "PR:HC": 0.5,  # high and changed
              "PR:LU": 0.62,
              "PR:HU": 0.27,
              "UI:N": 0.85,
              "UI:R": 0.62,
              "S:U": 0,  # Not real value
              "S:C": 1,  # Not real value
              "C:N": 0,
              "C:L": 0.22,
              "C:H": 0.56,
              "I:N": 0,
              "I:L": 0.22,
              "I:H": 0.56,
              "A:N": 0,
              "A:L": 0.22,
              "A:H": 0.56}
    environmentalScores = {"CR:X": 1,
                           "CR:L": 0.5,
                           "CR:M": 1,
                           "CR:H": 1.5,
                           "IR:X": 1,
                           "IR:L": 0.5,
                           "IR:M": 1,
                           "IR:H": 1.5,
                           "AR:X": 1,
                           "AR:L": 0.5,
                           "AR:M": 1,
                           "AR:H": 1.5,
                           "MAV:X": 1,
                           "MAV:N": 0.85,
                           "MAV:A": 0.62,
                           "MAV:L": 0.55,
                           "MAV:P": 0.2,
                           "MAC:X": 1,
                           "MAC:L": 0.77,
                           "MAC:H": 0.44,
                           "MPR:X": 1,
                           "MPR:N": 0.85,
                           "MPR:L": 0.62,
                           "MPR:H": 0.27,
                           "MPR:LMSC": 0.68,  # MPR:L AND MS:C
                           "MPR:LSCMSX": 0.68,  # MPR:L AND MS:X AND S:C
                           "MPR:HMSC": 0.5,  # MPR:H AND MS:C
                           "MPR:HSCMSX": 0.5,  # MPR:H AND MS:X AND S:C
                           "MUI:X": 1,
                           "MUI:N": 0.85,
                           "MUI:R": 0.62,
                           "MS:X": "X",
                           "MS:U": "U",
                           "MS:C": "C",
                           "MC:X": 1,
                           "MC:N": 0,
                           "MC:L": 0.22,
                           "MC:H": 0.56,
                           "MI:X": 1,
                           "MI:N": 0,
                           "MI:L": 0.22,
                           "MI:H": 0.56,
                           "MA:X": 1,
                           "MA:N": 0,
                           "MA:L": 0.22,
                           "MA:H": 0.56}

    def __init__(self, vector):
        self.vector = re.sub(r'CVSS:3\.[01]\/', '', vector, re.I)
        self.extended = self.isExtended()
        # Basic Score
        self.av = 0
        self.ac = 0
        self.pr = 0
        self.ui = 0
        self.s = 0
        self.c = 0
        self.i = 0
        self.a = 0
        # Environmental Score
        self.cr = 1
        self.ir = 1
        self.ar = 1
        self.mav = 1
        self.mac = 1
        self.mpr = 1
        self.mui = 1
        self.ms = 1
        self.mc = 1
        self.mi = 1
        self.ma = 1
        #
        self.baseScore = 0
        self.environmentalScore = 0
        self.temporalScore = 0
        self.impact = 0
        self.exploitability = 0

    def isExtended(self):
        if len(self.vector.split('/')) > 8:
            return True
        else:
            return False

    def printBasicScore(self):
        print("Basic Score:\t", self.av, self.ac, self.pr, self.ui, self.s, self.c, self.i, self.a)
        return

    def printEnvironmentalScore(self):
        print("Environmental Score:\t", self.cr, self.ir, self.ar, self.mav, self.mac, self.mpr, self.mui, self.ms, self.mc, self.mi, self.ma)
        return

    def getCVSS(self):
        print(self.vector)
        av, ac, pr, ui, s, c, i, a = self.vector.split('/')
        print(av, ac, pr, ui, s, c, i, a, sep="   ")
        try:
            self.av = self.scores[av]
            self.ac = self.scores[ac]
            if pr == "PR:N":
                self.pr = self.scores[pr]
            else:
                if self.scores[s]:
                    self.pr = self.scores[pr + "C"]
                else:
                    self.pr = self.scores[pr + "U"]
            self.ui = self.scores[ui]
            self.s = self.scores[s]
            self.c = self.scores[c]
            self.i = self.scores[i]
            self.a = self.scores[a]
            self.printBasicScore()
        except KeyError as e:
            print("[ERROR] The provided vector is not correct")
            logging.info("Error found in %s" % e)
            sys.exit(0)
        else:
            return

    def getCVSSExtended(self):
        print(self.vector)
        av, ac, pr, ui, s, c, i, a, extended = self.vector.split('/', maxsplit=8)
        extended = extended.split('/')
        try:
            self.av = self.scores[av]
            self.ac = self.scores[ac]
            if pr == "PR:N":
                self.pr = self.scores[pr]
            else:
                if self.scores[s]:
                    self.pr = self.scores[pr + "C"]
                else:
                    self.pr = self.scores[pr + "U"]
            self.ui = self.scores[ui]
            self.s = self.scores[s]
            self.c = self.scores[c]
            self.i = self.scores[i]
            self.a = self.scores[a]
            self.printBasicScore()
        except KeyError as e:
            print("[ERROR] The provided vector is not correct")
            logging.info("Error found in %s" % e)
            sys.exit(0)
        else:
            for element in extended:
                try:
                    aux = self.environmentalScores[element]
                    metric = element.split(":")[0]
                except KeyError as e:
                    print("[ERROR] The provided vector is not correct")
                    logging.info("Error found in %s" % e)
                    sys.exit(0)
                else:
                    if metric == "CR":
                        self.cr = aux
                    elif metric == "IR":
                        self.ir = aux
                    elif metric == "AR":
                        self.ar = aux
                    elif metric == "MAV":
                        self.mav = aux
                    elif metric == "MAC":
                        self.mac = aux
                    elif metric == "MPR":
                        self.mpr = aux
                    elif metric == "MUI":
                        self.mui = aux
                    elif metric == "MS":
                        self.ms = aux
                    elif metric == "MC":
                        self.mc = aux
                    elif metric == "MI":
                        self.mi = aux
                    elif metric == "MA":
                        self.ma = aux
                    else:
                        continue
            self.printEnvironmentalScore()
            return

    def calculateValues(self):
        iss = 1 - ((1 - self.c) * (1 - self.i) * (1 - self.a))
        if iss == 0:
            return
        else:
            self.exploitability = 8.22 * self.av * self.ac * self.pr * self.ui
            if self.s:
                self.impact = 7.52 * (iss - 0.029) - 3.25 * pow((iss - 0.02), 15)
                self.baseScore = self.roundup(min(1.08 * (self.impact + self.exploitability), 10))
                if self.baseScore == 10:
                    exploitabilityAux = self.roundup(
                        (self.exploitability * 10 / (self.exploitability + self.impact) * 10) / 10)
                    impactAux = self.roundup((self.impact * 10 / (self.exploitability + self.impact) * 10) / 10)
                    logging.info("Impact: %f\t\tExploitability: %f" % (self.impact, self.exploitability))
                    logging.info("Impact (right): %f\tExploitability (right): %f" % (impactAux, exploitabilityAux))
                # exploitability = exploitabilityAux
                # impact =  impactAux
                else:
                    logging.info("Impact: %f\tExploitability: %f" % (self.impact, self.exploitability))
            else:
                self.impact = 6.42 * iss
                logging.info("Impact: %f\tExploitability: %f" % (self.impact, self.exploitability))
                self.baseScore = self.roundup(min(self.impact + self.exploitability, 10))

            self.baseScore = math.ceil(
                self.baseScore * 10) / 10  # Original formula= math.floor(old_value * 10**ndecimals) / 10**ndecimals
            logging.info("Base Score: %f" % self.baseScore)
            print(iss, self.impact, self.exploitability, self.baseScore)
            return

    def calculateValuesExtended(self):
        caux = self.mc if re.search("MC:[^X]",
                                    self.vector) else self.c  # Modified Confidentiality if MC and not MC:X value is found in vector
        iaux = self.mi if re.search("MI:[^X]", self.vector) else self.i
        aaux = self.ma if re.search("MA:[^X]", self.vector) else self.a
        print(self.cr, self.ir, self.ar, "\t,", caux, iaux, aaux)
        miss = min(1 - (1 - self.cr * caux) * (1 - self.ir * iaux) * (1 - self.ar * aaux), 0.915)

        if (re.search("MS:X", self.vector) and re.search("S:C", self.vector)) or re.search("MS:C", self.vector):
            self.impact = 7.52 * (miss - 0.029) - 3.25 * pow(miss * 0.9731 - 0.02, 13)
        else:
            self.impact = 6.42 * miss
        avaux = self.mav if re.search("MAV:[^X]", self.vector) else self.av
        acaux = self.mac if re.search("MAC:[^X]", self.vector) else self.ac
        praux = self.mpr if re.search("MPR:[^X]", self.vector) else self.pr
        uiaux = self.mui if re.search("MUI:[^X]", self.vector) else self.ui
        self.exploitability = 8.22 * avaux * acaux * praux * uiaux
        if self.impact == 0:
            pass
        elif (re.search("MS:X", self.vector) and re.search("S:C", self.vector)) or re.search("MS:C", self.vector):
            self.environmentalScore = self.roundup(min(1.08 * (self.impact + self.exploitability), 10))
        else:
            self.environmentalScore = self.roundup(min(self.impact + self.exploitability, 10))
        print(miss, self.impact, self.exploitability, self.environmentalScore)
        return

		return impact,exploitability,baseScore

def roundup(input):
	integer = round(input*100000)
	if (integer %10000) == 0:
		return integer/100000.0
	else:
		return (math.floor(integer/10000)+1) /10.0

    def createGraph(self, score, show):
        global counter
        #global lock
        labels = ['']
        impact = [self.impact]
        exploitability = [self.exploitability]
        # width = 0.35       # the width of the bars: can also be len(x) sequence
        width = 2

        fig, ax = plt.subplots(figsize=(12, 2.6))
        fig.subplots_adjust(bottom=0.30)

        p1 = ax.barh(labels, impact, width, label='Impacto', color='#4e81bd', align='center')
        p2 = ax.barh(labels, exploitability, width, left=impact, label='Explotabilidad', color='#c1504c')
        # ay.bar(labels, exploitability, width,bottom=impact,label='Explotabilidad',color='#c1504c')
        # ax.set_xlabel("Impacto\tExplotabilidad")

        # ax.legend()
        # ax.bar_label(p1,label_type='edge')
        ax.text(5, 0, str(score), horizontalalignment='center', verticalalignment='center', fontsize=12)
        ax.legend(loc='upper center', bbox_to_anchor=(0.5, -0.2),
                  fancybox=False, shadow=False, ncol=2)
        ax.spines["right"].set_visible(False)
        ax.spines["top"].set_visible(False)
        ax.set_axisbelow(True)
        ax.grid(color="#d7d7d7")
        plt.xlim([0, 10])
        plt.xticks(range(11))
        plt.ylabel("Puntuación total", rotation="horizontal", labelpad=40)
        #lock.acquire()
        filename = "cvss_%s.png" % str(counter)
        # plt.figure(num="Vector %s" %str(counter))
        counter += 1
        plt.savefig(filename, transparent=True, bbox_inches='tight')
        #lock.release()
        if show:
            plt.show()


# Variables
counter = 1
#lock = Lock()


# Definitions
def createCVSSVector(CVSSVector):
    if CVSSVector.isExtended():
        CVSSVector.getCVSSExtended()
        CVSSVector.calculateValuesExtended()
        CVSSVector.createGraph(CVSSVector.environmentalScore, show=args.show)
    else:
        CVSSVector.getCVSS()
        CVSSVector.calculateValues()
        CVSSVector.createGraph(CVSSVector.baseScore, show=args.show)
    return


# Argparse
parser = argparse.ArgumentParser()
inputGroup = parser.add_mutually_exclusive_group(required=True)
inputGroup.add_argument("-v", "--vector", dest="vector", help="CVSS Vector", nargs=1)
inputGroup.add_argument("-f", "--file", dest="file", help="File with multiple vectors, one per line", nargs=1)
parser.add_argument("-s", "--show", dest="show", help="Shows the graphic (pauses the script execution).",
                    action="store_true")
parser.add_argument("-V", "--verbose", dest="verbose", help="Verbose mode.", action="store_true")

args = parser.parse_args()

# Main
if __name__ == '__main__':
    if args.verbose:
        logging.basicConfig(level=logging.INFO)
    if args.vector:
        # createCVSSVector(args.vector[0])
        v = CVSSVector(args.vector[0])
        createCVSSVector(v)
    elif args.file:
        # with open(args.file[0], "r", encoding="utf-8") as file:
        #     lines = file.readlines()
        #     threads = 3#len(lines)
        #     with multiprocessing.Pool(threads) as pool:
        #         vectors = [(CVSSVector(line.rstrip("\n")),) for line in lines] #Try create an object while creating the pool
        #         #print(vectors)
        #         pool.starmap(createCVSSVector, iterable=vectors)
        #         pool.close()
        #         pool.join()
        with open(args.file[0], "r", encoding="utf-8") as file:
            for line in file:
                createCVSSVector(CVSSVector(line.rstrip("\n")))
    else:
        sys.exit(0)
