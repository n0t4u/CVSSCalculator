#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#Author: n0t4u
#Version: 0.1.2

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
counter=1

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

def calculateValues(av,ac,pr,ui,scope,confidentiality,integrity,availability):
	iss= 1-((1-confidentiality)*(1-integrity)*(1-availability))
	if iss == 0:
		return 0,0,0
	else:
		exploitability=8.22*av*ac*pr*ui
		if scope:
			impact=7.52*(iss-0.029)-3.25*pow((iss-0.02),15)
			baseScore = roundup(min(1.08*(impact+exploitability),10))
			if baseScore == 10:
				exploitabilityAux = roundup((exploitability*10/(exploitability+impact)*10)/10)
				impactAux = roundup((impact*10/(exploitability+impact)*10)/10)
				logging.info("Impact: %f\t\tExploitability: %f" %(impact,exploitability))
				logging.info("Impact (right): %f\tExploitability (right): %f" %(impactAux,exploitabilityAux))
				#exploitability = exploitabilityAux
				#impact =  impactAux
			else:
				logging.info("Impact: %f\tExploitability: %f" %(impact,exploitability))
		else:
			impact=6.42*iss
			logging.info("Impact: %f\tExploitability: %f" %(impact,exploitability))
			baseScore = roundup(min(impact+exploitability,10))
		
		
		baseScore=math.ceil(baseScore*10)/10 #Original formula= math.floor(old_value * 10**ndecimals) / 10**ndecimals
		logging.info("Base Score: %f" %baseScore)

		return impact,exploitability,baseScore

def roundup(input):
	integer = round(input*100000)
	if (integer %10000) == 0:
		return integer/100000.0
	else:
		return (math.floor(integer/10000)+1) /10.0

def createGraph(impact,exploitability,baseScore,show):
	global counter
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
	filename="cvss_%s.png" %int(counter)
	counter += 1
	plt.savefig(filename,transparent=True,bbox_inches='tight')
	if show:
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
		print(args.show)
		createGraph(impact,exploitability, baseScore, show=args.show)
	elif args.file:
		with open(args.file[0],"r",encoding="utf-8") as file:
			for line in file:
				impact, exploitability, baseScore =getCVSS(line.rstrip("\n"))
				createGraph(impact,exploitability, baseScore, show=False)
	else:
		sys.exit(0)