#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Author: n0t4u
# Version: 0.2.3

# Information obtained from:
# https://www.first.org/cvss/calculator/cvsscalc31.js
# https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator (show equations)

# Imports
import argparse
import logging
from termcolor import colored
import math
import matplotlib.pyplot as plt
import re
import sys


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
    temporalScores = {"E:X": 1,
                      "E:U": 0.91,
                      "E:P": 0.94,
                      "E:F": 0.97,
                      "E:H": 1,
                      "RL:X": 1,
                      "RL:O": 0.95,
                      "RL:T": 0.96,
                      "RL:W": 0.97,
                      "RL:U": 1,
                      "RC:X": 1,
                      "RC:U": 0.92,
                      "RC:R": 0.96,
                      "RC:C": 1,
                      }
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
        # Basic Score Metrics
        self.av = 0
        self.ac = 0
        self.pr = 0
        self.ui = 0
        self.s = 0
        self.c = 0
        self.i = 0
        self.a = 0
        # Temporal Score Metrics
        self.e = 1
        self.rl = 1
        self.rc = 1
        # Environmental Score Metrics
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
        self.temporalScore = 0
        self.environmentalScore = 0
        self.impact = 0
        self.exploitability = 0

    def isExtended(self):
        if len(self.vector.split('/')) > 8:
            return True
        else:
            return False

    def printBaseScore(self):
        print("Base Score:", self.baseScore)
        return

    def printTemporalScore(self):
        print("Temporal Score:", self.temporalScore)
        return

    def printEnvironmentalScore(self):
        print("Environmental Score:", self.environmentalScore)
        return

    def printBaseScoreMetrics(self):
        logging.info(colored("Basic Score Metrics:\t%s %s %s %s %s %s %s %s" % (self.av, self.ac, self.pr, self.ui, self.s, self.c, self.i, self.a), "cyan"))
        return

    def printTemporalScoreMetrics(self):
        logging.info(colored("Temporal Score Metrics:\t%s %s %s" % (self.e, self.rl, self.rc), "cyan"))
        return

    def printEnvironmentalScoreMetrics(self):
        logging.info(colored("Environmental Score Metrics:\t%s %s %s %s %s %s %s %s %s %s %s" % (
        self.cr, self.ir, self.ar, self.mav, self.mac, self.mpr, self.mui, self.ms, self.mc, self.mi, self.ma), "cyan"))
        return

    def getCVSS(self):
        print(self.vector)
        av, ac, pr, ui, s, c, i, a = self.vector.split('/')
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
            self.printBaseScoreMetrics()
        except KeyError as e:
            print("[ERROR] The provided vector is not correct")
            logging.info(colored("Error found in %s" % e, "cyan"))
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
            self.printBaseScoreMetrics()
        except KeyError as e:
            print("[ERROR] The provided vector is not correct")
            logging.info(colored("Error found in %s" % e, "cyan"))
            sys.exit(0)
        else:
            extendScores = self.temporalScores | self.environmentalScores
            for element in extended:
                try:
                    if element == "MPR:L":
                        if re.search(r'MS:C', self.vector):
                            element = "MPR:LMSC"
                        elif self.c:
                            element = "MPR:LSCMSX"
                    elif element == "MPR:H":
                        if re.search(r'MS:C', self.vector):
                            element = "MPR:HMSC"
                        elif self.c:
                            element = "MPR:HSCMSX"
                    aux = extendScores[element]
                    metric = element.split(":")[0]
                except KeyError as e:
                    print("[ERROR] The provided vector is not correct")
                    logging.info(colored("Error found in %s (getCVSSExtended)" % e, "cyan"))
                    sys.exit(0)
                else:
                    if metric == "E":
                        self.e = aux
                    elif metric == "RL":
                        self.rl = aux
                    elif metric == "RC":
                        self.rc = aux
                    elif metric == "CR":
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
            self.printTemporalScoreMetrics()
            self.printEnvironmentalScoreMetrics()
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
                    logging.info(
                        colored("Impact: %f\t\tExploitability: %f" % (self.impact, self.exploitability), "cyan"))
                    logging.info(
                        colored("Impact (right): %f\tExploitability (right): %f" % (impactAux, exploitabilityAux),
                                "cyan"))
                else:
                    logging.info(colored("Impact: %f\tExploitability: %f" % (self.impact, self.exploitability), "cyan"))
            else:
                self.impact = 6.42 * iss
                logging.info(colored("Impact: %f\tExploitability: %f" % (self.impact, self.exploitability), "cyan"))
                self.baseScore = self.roundup(min(self.impact + self.exploitability, 10))

            self.baseScore = math.ceil(
                self.baseScore * 10) / 10  # Original formula= math.floor(old_value * 10**ndecimals) / 10**ndecimals
            self.printBaseScore()
            logging.info(colored("ISS:%f\tImpact:%f\tExploitability:%f\tBase Score:%f" % (
            iss, self.impact, self.exploitability, self.baseScore), "cyan"))
            return


    def calculateValuesExtended(self):
        # Temporal
        self.temporalScore = self.roundup(self.baseScore * self.e * self.rl * self.rc)
        self.printTemporalScore()
        # Environmental
        # Modified Confidentiality if MC and not MC:X value is found in vector
        caux = self.mc if re.search("MC:[^X]", self.vector) else self.c
        iaux = self.mi if re.search("MI:[^X]", self.vector) else self.i
        aaux = self.ma if re.search("MA:[^X]", self.vector) else self.a
        logging.info(
            colored("Enviromental vs Base (CIA):\t%f %f %f \t %f %f %f" % (self.cr, self.ir, self.ar, caux, iaux, aaux),
                    "cyan"))
        miss = min(1 - (1 - self.cr * caux) * (1 - self.ir * iaux) * (1 - self.ar * aaux), 0.915)

        if re.search("S:C", self.vector) or re.search("MS:C", self.vector):
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
        elif re.search("S:C", self.vector) or re.search("MS:C", self.vector):
            self.environmentalScore = self.roundup(
                self.roundup(min(1.08 * (self.impact + self.exploitability), 10)) * self.e * self.rl * self.rc)
        else:
            self.environmentalScore = self.roundup(
                self.roundup(min(self.impact + self.exploitability, 10)) * self.e * self.rl * self.rc)
        self.printEnvironmentalScore()
        logging.info(colored("MISS:%f\tModified Impact:%f\t Modified Exploitability:%f\tEnvironmental Score:%f" % (
        miss, self.impact, self.exploitability, self.environmentalScore), "cyan"))
        return

    def roundup(self, input):
        integer = round(input * 100000)
        if (integer % 10000) == 0:
            return integer / 100000.0
        else:
            return (math.floor(integer / 10000) + 1) / 10.0

    def createGraph(self, score, show, offset):
        global counter
        labels = ['']
        impact = [self.impact]
        exploitability = [self.exploitability]
        # width = 0.35       # the width of the bars: can also be len(x) sequence
        width = 2

        fig, ax = plt.subplots(figsize=(12, 2.6))
        fig.subplots_adjust(bottom=0.30)

        p1 = ax.barh(labels, impact, width, label=languages[lang][0+offset], color='#4e81bd', align='center')
        p2 = ax.barh(labels, exploitability, width, left=impact, label=languages[lang][1+offset], color='#c1504c')
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
        plt.ylabel(languages[lang][0], rotation="horizontal", labelpad=40)
        filename = "cvss_%s.png" % str(counter)
        # plt.figure(num="Vector %s" %str(counter))
        counter += 1
        plt.savefig(filename, transparent=True, bbox_inches='tight')
        if show:
            plt.show()


# Variables
counter = 1
languages ={"spanish":["Puntuación Total", "Impacto", "Explotabilidad", "Impacto modificado", "Explotabilidad modificada"],
            "english":["Total Scoring", "Impact", "Exploitability", "Modified impact", "Modified exploitability"]}
lang="spanish"


# Definitions
def createCVSSVector(CVSSVector):
    if CVSSVector.isExtended():
        CVSSVector.getCVSSExtended()
        CVSSVector.calculateValues()
        CVSSVector.calculateValuesExtended()
        CVSSVector.createGraph(CVSSVector.environmentalScore, show=args.show, offset=3)
    else:
        CVSSVector.getCVSS()
        CVSSVector.calculateValues()
        CVSSVector.createGraph(CVSSVector.baseScore, show=args.show, offset=1)
    return


# Argparse
parser = argparse.ArgumentParser()
inputGroup = parser.add_mutually_exclusive_group(required=True)
inputGroup.add_argument("-v", "--vector", dest="vector", help="CVSS Vector", nargs=1)
inputGroup.add_argument("-f", "--file", dest="file", help="File with multiple vectors, one per line", nargs=1)
parser.add_argument("-s", "--show", dest="show", help="Shows the graphic (pauses the script execution).",
                    action="store_true")
parser.add_argument("-V", "--verbose", dest="verbose", help="Verbose mode.", action="store_true")
languageGroup = parser.add_mutually_exclusive_group(required=False)
languageGroup.add_argument("-es", dest="es", help="Español", action="store_true")
languageGroup.add_argument("-en", dest="en", help="English", action="store_true")

args = parser.parse_args()

# Main
if __name__ == '__main__':
    if args.verbose:
        logging.basicConfig(level=logging.INFO)
    if args.en:
        lang="english"
    if args.vector:
        createCVSSVector(CVSSVector(args.vector[0]))
    elif args.file:
        with open(args.file[0], "r", encoding="utf-8") as file:
            for line in file:
                createCVSSVector(CVSSVector(line.rstrip("\n")))
    else:
        sys.exit(0)
