#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#Author: n0t4u
#Version: 0.1.1

#Imports
import argparse
import logging
from termcolor import colored
import math
import matplotlib.pyplot as plt
import re
import sys

#Variables
scores={
	"AV:N":0.85,
	"AV:A":0.6,
	"AV:L":0.55,
	"AV:P":0.2,
	"AC:L":0.77,
	"AC:H":0.44,
	"PR:N":0.85,
	"PR:LC":0.68, #low and changed
	"PR:HC":0.5, #high and changed
	"PR:LU":0.62,
	"PR:HU":0.27,
	"UI:N":0.85,
	"UI:R":0.62,
	"S:U":0, #Not real value
	"S:C":1, #Not real value
	"C:N":0,
	"C:L":0.22,
	"C:H":0.56,
	"I:N":0,
	"I:L":0.22,
	"I:H":0.56,
	"A:N":0,
	"A:L":0.22,
	"A:H":0.56
}

#Definitions
def getCVSS(vector):
	vector =re.sub(r'CVSS:3\.[01]{1}\/','',vector,re.I)
	print(vector)
	av,ac,pr,ui,s,c,i,a= vector.split('/')
	print(av,ac,pr,ui,s,c,i,a,sep="\t")
	try:
		attackVector=scores[av]
		attackComplexity=scores[ac]
		if pr=="PR:N":
			privilegedRequired=scores[pr]
		else:
			if scores[s]:

				privilegedRequired=scores[pr+"C"]
			else:
				privilegedRequired=scores[pr+"U"]
		userInteraction=scores[ui]
		confidentiality=scores[c]
		integrity=scores[i]
		availability=scores[a]
		print(attackVector,attackComplexity,privilegedRequired,userInteraction,scores[s],confidentiality,integrity,availability,sep="\t")
	except KeyError as e:
		print("[ERROR] The provided vector is not correct")
		logging.info("Error found in %s" %e)
		sys.exit(0)
	else:
		return calculateValues(attackVector,attackComplexity,privilegedRequired,userInteraction,scores[s],confidentiality,integrity,availability)

def getCVSSfromFile(filename):
	return

def calculateValues(av,ac,pr,ui,scope,confidentiality,integrity,availability):
	iss= 1-((1-confidentiality)*(1-integrity)*(1-availability))
	if iss == 0:
		return 0,0,0
	else:
		exploitability=8.22*av*ac*pr*ui
		if scope:
			impact=7.52*(iss-0.029)-3.25*pow((iss-0.02),15)
			baseScore = min(1.08*(impact+exploitability),10)
		else:
			impact=6.42*iss
			baseScore = min(impact+exploitability,10)
		
		logging.info("Impact: %f\tExploitability: %f" %(impact,exploitability))
		baseScore=math.ceil(baseScore*10)/10 #Original formula= math.floor(old_value * 10**ndecimals) / 10**ndecimals
		logging.info("Base Score: %f" %baseScore)

		return impact,exploitability,baseScore

def createGraph(impact,exploitability,baseScore):
	labels = ['']
	impact = [impact]
	exploitability = [exploitability]
	#width = 0.35       # the width of the bars: can also be len(x) sequence
	width = 2

	fig, ax = plt.subplots(figsize=(12,2.6))
	fig.subplots_adjust(bottom=0.30)

	p1=ax.barh(labels, impact, width, label='Impacto',color='#4e81bd',align='center')
	p2=ax.barh(labels, exploitability, width,left=impact,label='Explotabilidad',color='#c1504c')
	#ay.bar(labels, exploitability, width,bottom=impact,label='Explotabilidad',color='#c1504c')
	#ax.set_xlabel("Impacto\tExplotabilidad")

	#ax.legend()
	#ax.bar_label(p1,label_type='edge')
	ax.text(5,0,str(baseScore), horizontalalignment='center',verticalalignment='center', fontsize=12)
	ax.legend(loc='upper center', bbox_to_anchor=(0.5, -0.2),
          fancybox=False, shadow=False, ncol=2)
	ax.spines["right"].set_visible(False)
	ax.spines["top"].set_visible(False)
	ax.set_axisbelow(True)
	ax.grid(color="#d7d7d7")
	plt.xlim([0,10])
	plt.xticks(range(11))
	plt.ylabel("Puntuación total", rotation="horizontal", labelpad=40)
	plt.savefig('cvss.png',transparent=True,bbox_inches='tight')
	if args.show:
		plt.show()

#Argparse
parser= argparse.ArgumentParser()
inputGroup= parser.add_mutually_exclusive_group(required=True)
inputGroup.add_argument("-v","--vector",dest="vector",help="CVSS Vector",nargs=1)
inputGroup.add_argument("-f","--file",dest="file",help="File with multiple vectors, one per line",nargs=1)
parser.add_argument("-s","--show",dest="show", help="Shows the graphic (pauses the script execution).", action="store_true")
parser.add_argument("-V","--verbose",dest="verbose", help="Verbose mode.", action="store_true")


args = parser.parse_args()
#Main
if __name__ == '__main__':
	if args.verbose:
		logging.basicConfig(level=logging.INFO)
	if args.vector:
		impact, exploitability, baseScore =getCVSS(args.vector[0])
	elif args.file:
		getCVSSfromFile(args.file[0])
	else:
		sys.exit(0)
	
	createGraph(impact,exploitability, baseScore)