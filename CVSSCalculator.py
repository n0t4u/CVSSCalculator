#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Author: n0t4u
# Version: 1.0.1

# Information obtained from:
# https://www.first.org/cvss/v4.0/specification-document
# https://github.com/FIRSTdotorg/cvss-v4-calculator/blob/main/cvss_lookup.js
# https://www.first.org/cvss/calculator/app.js?v=7

# Imports
import argparse
import logging
import matplotlib.pyplot as plt
import re
import sys
from tabulate import tabulate

# Variables
SCORES = {"000000": 10,
			"000001": 9.9,
			"000010": 9.8,
			"000011": 9.5,
			"000020": 9.5,
			"000021": 9.2,
			"000100": 10,
			"000101": 9.6,
			"000110": 9.3,
			"000111": 8.7,
			"000120": 9.1,
			"000121": 8.1,
			"000200": 9.3,
			"000201": 9,
			"000210": 8.9,
			"000211": 8,
			"000220": 8.1,
			"000221": 6.8,
			"001000": 9.8,
			"001001": 9.5,
			"001010": 9.5,
			"001011": 9.2,
			"001020": 9,
			"001021": 8.4,
			"001100": 9.3,
			"001101": 9.2,
			"001110": 8.9,
			"001111": 8.1,
			"001120": 8.1,
			"001121": 6.5,
			"001200": 8.8,
			"001201": 8,
			"001210": 7.8,
			"001211": 7,
			"001220": 6.9,
			"001221": 4.8,
			"002001": 9.2,
			"002011": 8.2,
			"002021": 7.2,
			"002101": 7.9,
			"002111": 6.9,
			"002121": 5,
			"002201": 6.9,
			"002211": 5.5,
			"002221": 2.7,
			"010000": 9.9,
			"010001": 9.7,
			"010010": 9.5,
			"010011": 9.2,
			"010020": 9.2,
			"010021": 8.5,
			"010100": 9.5,
			"010101": 9.1,
			"010110": 9,
			"010111": 8.3,
			"010120": 8.4,
			"010121": 7.1,
			"010200": 9.2,
			"010201": 8.1,
			"010210": 8.2,
			"010211": 7.1,
			"010220": 7.2,
			"010221": 5.3,
			"011000": 9.5,
			"011001": 9.3,
			"011010": 9.2,
			"011011": 8.5,
			"011020": 8.5,
			"011021": 7.3,
			"011100": 9.2,
			"011101": 8.2,
			"011110": 8,
			"011111": 7.2,
			"011120": 7,
			"011121": 5.9,
			"011200": 8.4,
			"011201": 7,
			"011210": 7.1,
			"011211": 5.2,
			"011220": 5,
			"011221": 3,
			"012001": 8.6,
			"012011": 7.5,
			"012021": 5.2,
			"012101": 7.1,
			"012111": 5.2,
			"012121": 2.9,
			"012201": 6.3,
			"012211": 2.9,
			"012221": 1.7,
			"100000": 9.8,
			"100001": 9.5,
			"100010": 9.4,
			"100011": 8.7,
			"100020": 9.1,
			"100021": 8.1,
			"100100": 9.4,
			"100101": 8.9,
			"100110": 8.6,
			"100111": 7.4,
			"100120": 7.7,
			"100121": 6.4,
			"100200": 8.7,
			"100201": 7.5,
			"100210": 7.4,
			"100211": 6.3,
			"100220": 6.3,
			"100221": 4.9,
			"101000": 9.4,
			"101001": 8.9,
			"101010": 8.8,
			"101011": 7.7,
			"101020": 7.6,
			"101021": 6.7,
			"101100": 8.6,
			"101101": 7.6,
			"101110": 7.4,
			"101111": 5.8,
			"101120": 5.9,
			"101121": 5,
			"101200": 7.2,
			"101201": 5.7,
			"101210": 5.7,
			"101211": 5.2,
			"101220": 5.2,
			"101221": 2.5,
			"102001": 8.3,
			"102011": 7,
			"102021": 5.4,
			"102101": 6.5,
			"102111": 5.8,
			"102121": 2.6,
			"102201": 5.3,
			"102211": 2.1,
			"102221": 1.3,
			"110000": 9.5,
			"110001": 9,
			"110010": 8.8,
			"110011": 7.6,
			"110020": 7.6,
			"110021": 7,
			"110100": 9,
			"110101": 7.7,
			"110110": 7.5,
			"110111": 6.2,
			"110120": 6.1,
			"110121": 5.3,
			"110200": 7.7,
			"110201": 6.6,
			"110210": 6.8,
			"110211": 5.9,
			"110220": 5.2,
			"110221": 3,
			"111000": 8.9,
			"111001": 7.8,
			"111010": 7.6,
			"111011": 6.7,
			"111020": 6.2,
			"111021": 5.8,
			"111100": 7.4,
			"111101": 5.9,
			"111110": 5.7,
			"111111": 5.7,
			"111120": 4.7,
			"111121": 2.3,
			"111200": 6.1,
			"111201": 5.2,
			"111210": 5.7,
			"111211": 2.9,
			"111220": 2.4,
			"111221": 1.6,
			"112001": 7.1,
			"112011": 5.9,
			"112021": 3,
			"112101": 5.8,
			"112111": 2.6,
			"112121": 1.5,
			"112201": 2.3,
			"112211": 1.3,
			"112221": 0.6,
			"200000": 9.3,
			"200001": 8.7,
			"200010": 8.6,
			"200011": 7.2,
			"200020": 7.5,
			"200021": 5.8,
			"200100": 8.6,
			"200101": 7.4,
			"200110": 7.4,
			"200111": 6.1,
			"200120": 5.6,
			"200121": 3.4,
			"200200": 7,
			"200201": 5.4,
			"200210": 5.2,
			"200211": 4,
			"200220": 4,
			"200221": 2.2,
			"201000": 8.5,
			"201001": 7.5,
			"201010": 7.4,
			"201011": 5.5,
			"201020": 6.2,
			"201021": 5.1,
			"201100": 7.2,
			"201101": 5.7,
			"201110": 5.5,
			"201111": 4.1,
			"201120": 4.6,
			"201121": 1.9,
			"201200": 5.3,
			"201201": 3.6,
			"201210": 3.4,
			"201211": 1.9,
			"201220": 1.9,
			"201221": 0.8,
			"202001": 6.4,
			"202011": 5.1,
			"202021": 2,
			"202101": 4.7,
			"202111": 2.1,
			"202121": 1.1,
			"202201": 2.4,
			"202211": 0.9,
			"202221": 0.4,
			"210000": 8.8,
			"210001": 7.5,
			"210010": 7.3,
			"210011": 5.3,
			"210020": 6,
			"210021": 5,
			"210100": 7.3,
			"210101": 5.5,
			"210110": 5.9,
			"210111": 4,
			"210120": 4.1,
			"210121": 2,
			"210200": 5.4,
			"210201": 4.3,
			"210210": 4.5,
			"210211": 2.2,
			"210220": 2,
			"210221": 1.1,
			"211000": 7.5,
			"211001": 5.5,
			"211010": 5.8,
			"211011": 4.5,
			"211020": 4,
			"211021": 2.1,
			"211100": 6.1,
			"211101": 5.1,
			"211110": 4.8,
			"211111": 1.8,
			"211120": 2,
			"211121": 0.9,
			"211200": 4.6,
			"211201": 1.8,
			"211210": 1.7,
			"211211": 0.7,
			"211220": 0.8,
			"211221": 0.2,
			"212001": 5.3,
			"212011": 2.4,
			"212021": 1.4,
			"212101": 2.4,
			"212111": 1.2,
			"212121": 0.5,
			"212201": 1,
			"212211": 0.3,
			"212221": 0.1}

##
AVLEVELS = {"N": 0.0, "A": 0.1, "L": 0.2, "P": 0.3}
PRLEVELS = {"N": 0.0, "L": 0.1, "H": 0.2}
UILEVELS = {"N": 0.0, "P": 0.1, "A": 0.2}
ACLEVELS = {'L': 0.0, 'H': 0.1}
ATLEVELS = {'N': 0.0, 'P': 0.1}
VCLEVELS = {'H': 0.0, 'L': 0.1, 'N': 0.2}
VILEVELS = {'H': 0.0, 'L': 0.1, 'N': 0.2}
VALEVELS = {'H': 0.0, 'L': 0.1, 'N': 0.2}
SCLEVELS = {'H': 0.1, 'L': 0.2, 'N': 0.3}
SILEVELS = {'S': 0.0, 'H': 0.1, 'L': 0.2, 'N': 0.3}
SALEVELS = {'S': 0.0, 'H': 0.1, 'L': 0.2, 'N': 0.3}
CRLEVELS = {'X': 0.0, 'H': 0.0, 'M': 0.1, 'L': 0.2}  # Added CR:X
IRLEVELS = {'X': 0.0, 'H': 0.0, 'M': 0.1, 'L': 0.2}  # Added IR:X
ARLEVELS = {'X': 0.0, 'H': 0.0, 'M': 0.1, 'L': 0.2}  # Added AR:X
ELEVELS = {'X': 0.0, 'U': 0.2, 'P': 0.1, 'A': 0.0}  # Added E:X

MAXVECTORS = {
	"eq1": {
		0: ["AV:N/PR:N/UI:N/"],
		1: ["AV:A/PR:N/UI:N/", "AV:N/PR:L/UI:N/", "AV:N/PR:N/UI:P/"],
		2: ["AV:P/PR:N/UI:N/", "AV:A/PR:L/UI:P/"]},
	"eq2": {
		0: ["AC:L/AT:N/"],
		1: ["AC:H/AT:N/", "AC:L/AT:P/"]},
	#EQ3+EQ6
	"eq3": {
		0: {
			0: ["VC:H/VI:H/VA:H/CR:H/IR:H/AR:H/"],
			1: ["VC:H/VI:H/VA:L/CR:M/IR:M/AR:H/", "VC:H/VI:H/VA:H/CR:M/IR:M/AR:M/"]},
		1: {
			0: ["VC:L/VI:H/VA:H/CR:H/IR:H/AR:H/", "VC:H/VI:L/VA:H/CR:H/IR:H/AR:H/"],
			1: ["VC:L/VI:H/VA:L/CR:H/IR:M/AR:H/", "VC:L/VI:H/VA:H/CR:H/IR:M/AR:M/", "VC:H/VI:L/VA:H/CR:M/IR:H/AR:M/",
				"VC:H/VI:L/VA:L/CR:M/IR:H/AR:H/", "VC:L/VI:L/VA:H/CR:H/IR:H/AR:M/"]},
		2: {
			1: ["VC:L/VI:L/VA:L/CR:H/IR:H/AR:H/"]}},
	"eq4": {
		0: ["SC:H/SI:S/SA:S/"],
		1: ["SC:H/SI:H/SA:H/"],
		2: ["SC:L/SI:L/SA:L/"]},
	"eq5": {
		0: ["E:A/"],
		1: ["E:P/"],
		2: ["E:U/"]}}

MAXSEVERITY = {
	"eq1": {0: 1, 1: 4, 2: 5},
	"eq2": {0: 1, 1: 2},
	"eq36": {
		0: {0: 7, 1: 6},
		1: {0: 8, 1: 8},
		2: {1: 10}},
	"eq4": {0: 6, 1: 5, 2: 4},
	"eq5": {0: 1, 1: 1, 2: 1}
}

lang = "spanish"
langTexts = {
	"spanish": ["Puntuación Total", "Explotabilidad", "Complejidad", "Sistema vulnerable", "Sistema subsecuente",
				"Explotación", "Requisitos de seguridad", "Nivel"],
	"english": ["Total Scoring", "Exploitability", "Complexity", "Vulnerable system", "Subsequent system",
				"Exploitation", "Security requirements", "Level"]}
langLevels = {"spanish": ["Alto", "Medio", "Bajo"],
			  "english": ["High", "Medium", "Low"]}
counter = 1


# Classes
class CVSSVector:
	vector = ""
	macroVector = []
	macroVectorScore = 0
	finalScore = 0
	metrics = {}
	auxMetrics = {}
	extended = False

	def __init__(self, vector):
		self.vector = re.sub(r'CVSS:4\.0/', '', vector, re.I)
		self.extended = self.isExtended()
		self.macroVector = ["X", "X", "X", "X", "X", "X"]
		self.metrics = {
			"AV": "",  # BASE METRICS ##Exploitability Metrics
			"AC": "",
			"AT": "",
			"PR": "",
			"UI": "",
			"VC": "",  ##Vulnerable System Impact Metrics
			"VI": "",
			"VA": "",
			"SC": "",  ##Subsequent System Impact Metrics
			"SI": "",
			"SA": "",
			"S": "X",  # SUPLEMENTAL METRICS
			"AU": "X",
			"R": "X",
			"V": "X",
			"RE": "X",
			"U": "X",
			"MAV": "X",  # ENVIRONMENTAL (MODIFIED BASE METRICS) ##Exploitability Metrics
			"MAC": "X",
			"MAT": "X",
			"MPR": "X",
			"MUI": "X",
			"MVC": "X",  ##Vulnerable System Impact Metrics
			"MVI": "X",
			"MVA": "X",
			"MSC": "X",  ##Vulnerable Subsequent System Impact Metrics
			"MSI": "X",
			"MSA": "X",
			"CR": "X",  ##ENVIRONMENTAL (SECURITY REQUIREMENTS)
			"IR": "X",
			"AR": "X",
			"E": "X"  # THREAT METRICS
		}
		self.auxMetrics = {
			"AV": "",  # BASE METRICS ##Exploitability Metrics
			"AC": "",
			"AT": "",
			"PR": "",
			"UI": "",
			"VC": "",  ##Vulnerable System Impact Metrics
			"VI": "",
			"VA": "",
			"SC": "",  ##Subsequent System Impact Metrics
			"SI": "",
			"SA": ""
		}

	def isExtended(self):
		if len(self.vector.split('/')) > 11:
			return True
		else:
			return False

	def setMetricValues(self):
		print(self.vector)
		subVectors = self.vector.split('/')
		for subVector in subVectors:
			try:
				key, value = subVector.split(':')
				self.metrics[key] = value
			except KeyError as e:
				print("[ERROR] The provided vector is not correct")
				logging.info("Error found in{}".format(e))
				sys.exit(0)
		return

	def getMetricValue(self, metric):
		return self.metrics[metric]

	def getMacroVector(self):
		# If impact metrics are None, then the score is 0.
		if self.auxMetrics["VC"] == "N" and self.auxMetrics["VI"] == "N" and self.auxMetrics["VA"] == "N" and \
				self.auxMetrics["SC"] == "N" and self.auxMetrics["SI"] == "N" and self.auxMetrics["SA"] == "N":
			self.macroVectorScore = 0.0
		else:
			# Get MacroVector numbers from every equation.
			self.macroVector[0] = self.getEQ1()
			self.macroVector[1] = self.getEQ2()
			self.macroVector[2] = self.getEQ3()
			self.macroVector[3] = self.getEQ4()
			self.macroVector[4] = self.getEQ5()
			self.macroVector[5] = self.getEQ6()
			self.macroVectorScore = self.cvssLookup()
		print("Equations Code:\t" + "".join(map(str, self.macroVector)))
		print("MacroVector Score:\t{}".format(self.macroVectorScore))
		return

	def checkEnvironmentalMetrics(self):
		# If set, environmental metrics overwrite base metrics
		if self.isExtended():
			self.auxMetrics["AV"] = self.metrics["AV"] if self.metrics["MAV"] == "X" else self.metrics["MAV"]
			self.auxMetrics["AC"] = self.metrics["AC"] if self.metrics["MAC"] == "X" else self.metrics["MAC"]
			self.auxMetrics["AT"] = self.metrics["AT"] if self.metrics["MAT"] == "X" else self.metrics["MAT"]
			self.auxMetrics["PR"] = self.metrics["PR"] if self.metrics["MPR"] == "X" else self.metrics["MPR"]
			self.auxMetrics["UI"] = self.metrics["UI"] if self.metrics["MUI"] == "X" else self.metrics["MUI"]
			self.auxMetrics["VC"] = self.metrics["VC"] if self.metrics["MVC"] == "X" else self.metrics["MVC"]
			self.auxMetrics["VI"] = self.metrics["VI"] if self.metrics["MVI"] == "X" else self.metrics["MVI"]
			self.auxMetrics["VA"] = self.metrics["VA"] if self.metrics["MVA"] == "X" else self.metrics["MVA"]
			self.auxMetrics["SC"] = self.metrics["SC"] if self.metrics["MSC"] == "X" else self.metrics["MSC"]
			self.auxMetrics["SI"] = self.metrics["SI"] if self.metrics["MSI"] == "X" else self.metrics["MSI"]
			self.auxMetrics["SA"] = self.metrics["SA"] if self.metrics["MSA"] == "X" else self.metrics["MSA"]
		else:
			self.auxMetrics["AV"] = self.metrics["AV"]
			self.auxMetrics["AC"] = self.metrics["AC"]
			self.auxMetrics["AT"] = self.metrics["AT"]
			self.auxMetrics["PR"] = self.metrics["PR"]
			self.auxMetrics["UI"] = self.metrics["UI"]
			self.auxMetrics["VC"] = self.metrics["VC"]
			self.auxMetrics["VI"] = self.metrics["VI"]
			self.auxMetrics["VA"] = self.metrics["VA"]
			self.auxMetrics["SC"] = self.metrics["SC"]
			self.auxMetrics["SI"] = self.metrics["SI"]
			self.auxMetrics["SA"] = self.metrics["SA"]
		# print(self.metrics)
		# print(self.auxMetrics)
		return

	def getEQ1(self):
		if self.auxMetrics["AV"] == "N" and self.auxMetrics["PR"] == "N" and self.auxMetrics["UI"] == "N":
			return 0
		elif (self.auxMetrics["AV"] == "N" or self.auxMetrics["PR"] == "N" or self.auxMetrics["UI"] == "N") and not (
				self.auxMetrics["AV"] == "N" and self.auxMetrics["PR"] == "N" and self.auxMetrics["UI"] == "N") and not \
				self.auxMetrics["AV"] == "P":
			return 1
		elif self.auxMetrics["AV"] == "P" or not (
				self.auxMetrics["AV"] == "N" and self.auxMetrics["PR"] == "N" and self.auxMetrics["UI"] == "N"):
			return 2

	def getEQ2(self):
		if self.auxMetrics["AC"] == "L" and self.auxMetrics["AT"] == "N":
			return 0
		else:  # not (self.auxMetrics["AC"] == "L" and self.auxMetrics["AT"] == "N")
			return 1

	def getEQ3(self):
		if self.auxMetrics["VC"] == "H" and self.auxMetrics["VI"] == "H":
			return 0
		elif not (self.auxMetrics["VC"] == "H" and self.auxMetrics["VI"] == "H") and (
				self.auxMetrics["VC"] == "H" or self.auxMetrics["VI"] == "H" or self.auxMetrics["VA"] == "H"):
			return 1
		elif not (self.auxMetrics["VC"] == "H" or self.auxMetrics["VI"] == "H" or self.auxMetrics["VA"] == "H"):
			return 2

	def getEQ4(self):
		if self.metrics["MSI"] == "S" or self.metrics["MSA"] == "S":
			return 0
		elif not (self.metrics["MSI"] == "S" or self.metrics["MSA"] == "S") and (
				self.auxMetrics["SC"] == "H" or self.auxMetrics["SI"] == "H" or self.auxMetrics["SA"] == "H"):
			return 1
		elif not (self.metrics["MSI"] == "S" or self.metrics["MSA"] == "S") and not (
				self.auxMetrics["SC"] == "H" or self.auxMetrics["SI"] == "H" or self.auxMetrics["SA"] == "H"):
			return 2

	def getEQ5(self):
		# Modified to include E:X, which is considered as the worst case (E:A).
		if self.metrics["E"] == "A" or self.metrics["E"] == "X":
			return 0
		elif self.metrics["E"] == "P":
			return 1
		elif self.metrics["E"] == "U":
			return 2

	def getEQ6(self):
		#TODO. Modified self.metrics["VX"] == "H" to self.auxMetrics["VX"] == "H"
		# Modified to include CR:X, IR:X and AR:X, which are considered as its worst case (xR:H)
		if ((self.metrics["CR"] == "H" or self.metrics["CR"] == "X") and self.auxMetrics["VC"] == "H") or (
				(self.metrics["IR"] == "H" or self.metrics["IR"] == "X") and self.auxMetrics["VI"] == "H") or (
				(self.metrics["AR"] == "H" or self.metrics["AR"] == "X") and self.auxMetrics["VA"] == "H"):
			return 0
		elif not ((self.metrics["CR"] == "H" or self.metrics["CR"] == "X") and self.auxMetrics["VC"] == "H") and not (
				(self.metrics["IR"] == "H" or self.metrics["IR"] == "X") and self.auxMetrics["VI"] == "H") and not (
				(self.metrics["AR"] == "H" or self.metrics["AR"] == "X") and self.auxMetrics["VA"] == "H"):
			return 1

	def cvssLookup(self):
		code = "".join(map(str, self.macroVector))
		try:
			return SCORES[code]
		except KeyError as e:
			print("ERROR. Provide a right CVSS Vector.")
			logging.info(e)
			sys.exit(0)

	def cvssLookupVector(self, vector):
		auxVector = "00000" + str(vector)  # If vector is 10 we want 000010
		try:
			return SCORES[auxVector[-6:]]
		except:
			return None  # If the MacroVector does not exist, then a NaN, or equivalent, is returned.

	def getMacroVectorAsInt(self):
		return int("".join(map(str, self.macroVector)))

	def correctScore(self):
		# Get next lower MacroVector related to the calculated. This is done by adding one unit to each of the Equations results.
		intMacroVector = self.getMacroVectorAsInt()
		EQ1NextLowerMacro = intMacroVector + 100000
		EQ2NextLowerMacro = intMacroVector + 10000  # 010000
		if (self.macroVector[2] == 1 or self.macroVector[2] == 0) and self.macroVector[5] == 1:  # 01 --> 11 o 11 --> 21
			EQ36NextLowerMacro = intMacroVector + 1000  # 001000
		elif self.macroVector[2] == 1 and self.macroVector[5] == 0:  # 10 --> 11
			EQ36NextLowerMacro = intMacroVector + 1  # 000001
		elif self.macroVector[2] == 0 and self.macroVector[5] == 0:  # 00 -> 01 o 00 --> 10
			EQ36NextLowerMacroLeft = intMacroVector + 1  # 000001
			EQ36NextLowerMacroRight = intMacroVector + 1000  # 001000
		else:  # 21 --> 32 (Do not exist)
			EQ36NextLowerMacro = intMacroVector + 1001  # 001001
		EQ4NextLowerMacro = intMacroVector + 100  # 000100
		EQ5NextLowerMacro = intMacroVector + 10  # 000010

		# print("EQXNextLowerMacro:",EQ1NextLowerMacro,EQ2NextLowerMacro,"--",EQ4NextLowerMacro,EQ5NextLowerMacro,sep="\t")
		# Get the score related to these new MacroVectors.
		scoreEQ1NLM = self.cvssLookupVector(EQ1NextLowerMacro)
		scoreEQ2NLM = self.cvssLookupVector(EQ2NextLowerMacro)
		if self.macroVector[2] == 0 and self.macroVector[5] == 0:
			scoreEQ36NLMLeft = self.cvssLookupVector(EQ36NextLowerMacroLeft)
			scoreEQ36NLMRight = self.cvssLookupVector(EQ36NextLowerMacroRight)
			if scoreEQ36NLMLeft > scoreEQ36NLMRight:
				scoreEQ36NLM = scoreEQ36NLMLeft
			else:
				scoreEQ36NLM = scoreEQ36NLMRight
		else:
			scoreEQ36NLM = self.cvssLookupVector(EQ36NextLowerMacro)
		scoreEQ4NLM = self.cvssLookupVector(EQ4NextLowerMacro)
		scoreEQ5NLM = self.cvssLookupVector(EQ5NextLowerMacro)

		# Get all the highest severity vector(s) associated to a EQ. This can be found in tables 25-29 in the specification document.
		maxEQ1 = self.getEQMax(intMacroVector, 1)
		maxEQ2 = self.getEQMax(intMacroVector, 2)
		maxEQ36 = self.getEQMax(intMacroVector, 3)[self.macroVector[5]]
		maxEQ4 = self.getEQMax(intMacroVector, 4)
		maxEQ5 = self.getEQMax(intMacroVector, 5)

		print("maxEQX:", maxEQ1,maxEQ2,maxEQ36,maxEQ4,maxEQ5, sep="\t")

		# Concatenate all the max MacroVectors to get all the possibilities.
		maxVectors = []
		for max1 in maxEQ1:
			for max2 in maxEQ2:
				for max36 in maxEQ36:
					for max4 in maxEQ4:
						for max5 in maxEQ5:
							maxVectors.append(max1 + max2 + max36 + max4 + max5)

		# Get one maximum. It does not matter if there are more, with one is enough.
		for i in range(0, len(maxVectors)):
			maxVector = maxVectors[i]
			try:
				print(AVLEVELS[self.metrics["AV"]],AVLEVELS[self.extractValueMetric("AV", maxVector)], maxVector,sep="\t")
				severityDistAV = AVLEVELS[self.auxMetrics["AV"]] - AVLEVELS[self.extractValueMetric("AV", maxVector)]
				severityDistPR = PRLEVELS[self.auxMetrics["PR"]] - PRLEVELS[self.extractValueMetric("PR", maxVector)]
				severityDistUI = UILEVELS[self.auxMetrics["UI"]] - UILEVELS[self.extractValueMetric("UI", maxVector)]
				severityDistAC = ACLEVELS[self.auxMetrics["AC"]] - ACLEVELS[self.extractValueMetric("AC", maxVector)]
				severityDistAT = ATLEVELS[self.auxMetrics["AT"]] - ATLEVELS[self.extractValueMetric("AT", maxVector)]

				severityDistVC = VCLEVELS[self.auxMetrics["VC"]] - VCLEVELS[self.extractValueMetric("VC", maxVector)]
				severityDistVI = VILEVELS[self.auxMetrics["VI"]] - VILEVELS[self.extractValueMetric("VI", maxVector)]
				severityDistVA = VALEVELS[self.auxMetrics["VA"]] - VALEVELS[self.extractValueMetric("VA", maxVector)]

				severityDistSC = SCLEVELS[self.auxMetrics["SC"]] - SCLEVELS[self.extractValueMetric("SC", maxVector)]
				severityDistSI = SILEVELS[self.auxMetrics["SI"]] - SILEVELS[self.extractValueMetric("SI", maxVector)]
				severityDistSA = SALEVELS[self.auxMetrics["SA"]] - SALEVELS[self.extractValueMetric("SA", maxVector)]

				#Security Requirements cannot be modified as Base Metrics with the Modified Base Metrics, then they are not in the auxMetrics dictionary.
				severityDistCR = CRLEVELS[self.metrics["CR"]] - CRLEVELS[self.extractValueMetric("CR", maxVector)]
				severityDistIR = IRLEVELS[self.metrics["IR"]] - IRLEVELS[self.extractValueMetric("IR", maxVector)]
				severityDistAR = ARLEVELS[self.metrics["AR"]] - ARLEVELS[self.extractValueMetric("AR", maxVector)]
			except KeyError as e:
				raise e
				print("Value {} is not correct in vector {}".format(e, self.vector))
				sys.exit(0)

			# If any of these severity distances is lower than 0, then this is not the correct maximum.
			if severityDistAV < 0 or severityDistPR < 0 or severityDistUI < 0 or severityDistAC < 0 or severityDistAT < 0 or severityDistVC < 0 or severityDistVI < 0 or severityDistVA < 0 or severityDistSC < 0 or severityDistSI < 0 or severityDistSA < 0 or severityDistCR < 0 or severityDistIR < 0 or severityDistAR < 0:
				continue
			else:  # If several maximum exist, with getting one is enough.
				break

		currentSeverityDistEQ1 = severityDistAV + severityDistPR + severityDistUI
		currentSeverityDistEQ2 = severityDistAC + severityDistAT
		currentSeverityDistEQ36 = severityDistVC + severityDistVI + severityDistVA + severityDistCR + severityDistIR + severityDistAR
		currentSeverityDistEQ4 = severityDistSC + severityDistSI + severityDistSA
		currentSeverityDistEQ5 = 0

		# print("currentSeverityDistEQX:", currentSeverityDistEQ1, currentSeverityDistEQ2, currentSeverityDistEQ36, currentSeverityDistEQ4, currentSeverityDistEQ5, sep="\t")

		step = 0.1
		# print("MacroVector Score:\t{}".format(self.macroVectorScore))
		# print("scoreEQXNLM:",scoreEQ1NLM, scoreEQ2NLM, scoreEQ36NLM, scoreEQ4NLM, scoreEQ5NLM, sep="\t")

		# Try-Except for None (NaN)  next lower MacroVector equation score (scoreEQxNLM)
		try:
			availableDistanceEQ1 = self.macroVectorScore - scoreEQ1NLM
		except TypeError:
			availableDistanceEQ1 = None
		try:
			availableDistanceEQ2 = self.macroVectorScore - scoreEQ2NLM
		except TypeError:
			availableDistanceEQ2 = None
		try:
			availableDistanceEQ36 = self.macroVectorScore - scoreEQ36NLM
		except TypeError:
			availableDistanceEQ36 = None
		try:
			availableDistanceEQ4 = self.macroVectorScore - scoreEQ4NLM
		except TypeError:
			availableDistanceEQ4 = None
		try:
			availableDistanceEQ5 = self.macroVectorScore - scoreEQ5NLM
		except TypeError:
			availableDistanceEQ5 = None

		# percentNextEQ1Severity = 0
		# percentNextEQ2Severity = 0
		# percentNextEQ36Severity = 0
		# percentNextEQ4Severity = 0
		# percentNextEQ5Severity = 0

		maxSeverityEQ1 = MAXSEVERITY["eq1"][self.macroVector[0]] * step
		maxSeverityEQ2 = MAXSEVERITY["eq2"][self.macroVector[1]] * step
		maxSeverityEQ36 = MAXSEVERITY["eq36"][self.macroVector[2]][self.macroVector[5]] * step
		maxSeverityEQ4 = MAXSEVERITY["eq4"][self.macroVector[3]] * step
		maxSeverityEQ5 = MAXSEVERITY["eq5"][self.macroVector[4]] * step

		# Normalize the severity distances and get the mean distance.
		nExistingLower = 0

		normalizedSeverityEQ1 = 0
		normalizedSeverityEQ2 = 0
		normalizedSeverityEQ36 = 0
		normalizedSeverityEQ4 = 0
		normalizedSeverityEQ5 = 0

		# print("availableDistanceEQX",availableDistanceEQ1, availableDistanceEQ2 ,availableDistanceEQ36, availableDistanceEQ4, availableDistanceEQ5, sep="\t")

		if not availableDistanceEQ1 == None:
			nExistingLower += 1
			percentNextEQ1Severity = currentSeverityDistEQ1 / maxSeverityEQ1
			normalizedSeverityEQ1 = availableDistanceEQ1 * percentNextEQ1Severity
		if not availableDistanceEQ2 == None:
			nExistingLower += 1
			percentNextEQ2Severity = currentSeverityDistEQ2 / maxSeverityEQ2
			normalizedSeverityEQ2 = availableDistanceEQ2 * percentNextEQ2Severity
		if not availableDistanceEQ36 == None:
			nExistingLower += 1
			percentNextEQ36Severity = currentSeverityDistEQ36 / maxSeverityEQ36
			normalizedSeverityEQ36 = availableDistanceEQ36 * percentNextEQ36Severity
		if not availableDistanceEQ4 == None:
			nExistingLower += 1
			percentNextEQ4Severity = currentSeverityDistEQ4 / maxSeverityEQ4
			normalizedSeverityEQ4 = availableDistanceEQ4 * percentNextEQ4Severity
		if not availableDistanceEQ5 == None:
			nExistingLower += 1
			normalizedSeverityEQ5 = 0

		if nExistingLower == 0:
			meanDist = 0
		else:
			meanDist = (
								   normalizedSeverityEQ1 + normalizedSeverityEQ2 + normalizedSeverityEQ36 + normalizedSeverityEQ4 + normalizedSeverityEQ5) / nExistingLower
		# print("nExistingLower:\t{}".format(nExistingLower))
		# print("meanDist:\t{}".format(meanDist))

		# Check if values are between 0 and 10.
		self.finalScore = self.macroVectorScore - meanDist
		if self.finalScore < 0:
			self.finalScore = 0.0
		if self.finalScore > 10:
			self.finalScore = 10
		# Round to one decimal.
		self.finalScore = round(self.finalScore, 1)
		print("Final Score:\t{}".format(self.finalScore))

		return

	def getEQMax(self, intMacroVector, eqN):
		return MAXVECTORS["eq" + str(eqN)][self.macroVector[eqN - 1]]

	def extractValueMetric(self, metric, vector):
		subVector = re.split(metric, vector)[1]
		return subVector[1:2]  # Obtain only the second char which is the metric value. Ex: AV:N --> :N --> N

	def createTable(self):
		data = [[langTexts[lang][1], langLevels[lang][self.macroVector[0]]],
				[langTexts[lang][2], langLevels[lang][self.macroVector[1]]],
				[langTexts[lang][3], langLevels[lang][self.macroVector[2]]],
				[langTexts[lang][4], langLevels[lang][self.macroVector[3]]],
				[langTexts[lang][5], langLevels[lang][self.macroVector[4]]],
				[langTexts[lang][6], langLevels[lang][self.macroVector[5]]]]
		colNames = ['#', langTexts[lang][7]]
		print()
		print(tabulate(data, headers=colNames, ))
		return

	def createGraph(self, score, show):
		global counter
		labels = ['']
		width = 2

		fig, ax = plt.subplots(figsize=(12, 2.6))
		fig.subplots_adjust(bottom=0.3)

		p1 = ax.barh(labels, score, width, label=langTexts[lang][0], color='#4e81bd', align='center')
		ax.text(score / 2, 0, str(score), horizontalalignment='center', verticalalignment='center', fontsize=12)
		ax.spines["right"].set_visible(False)
		ax.spines["top"].set_visible(False)
		ax.set_axisbelow(True)
		ax.grid(color="#000000")
		plt.xlim([0, 10])
		plt.xticks(range(11))
		plt.ylabel(langTexts[lang][0], rotation="horizontal", labelpad=40)
		filename = "cvss_%s.png" % str(counter)
		counter += 1
		plt.savefig(filename, transparent=True, bbox_inches='tight')
		if show:
			plt.show()
		return


# Definitions
def createCVSSVector(CVSSVector):
	# Set all metrics
	CVSSVector.setMetricValues()
	# Check if any environmental metric modifies a base metric.
	CVSSVector.checkEnvironmentalMetrics()
	# Obtain MacroVector
	CVSSVector.getMacroVector()
	if not CVSSVector.macroVectorScore == 0:
		# Correct MacroVector. This has to be done because the same MacroVector is obtained for, for example, vulnerabilities with Attack Vector (AV) Adjacent (A) and Local (L).
		CVSSVector.correctScore()
	CVSSVector.createTable()
	CVSSVector.createGraph(CVSSVector.finalScore, show=args.show)
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
		logging.basicConfig(format='%(levelname)s:\t%(message)', level=logging.INFO)
	if args.en:
		lang = "english"
	if args.vector:
		createCVSSVector(CVSSVector(args.vector[0]))
	elif args.file:
		with open(args.file[0], "r", encoding="utf-8") as file:
			for line in file:
				createCVSSVector(CVSSVector(line.rstrip("\n")))
	else:
		sys.exit(0)
