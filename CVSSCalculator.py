#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#Author: n0t4u
#Version: 0.1.0

#Imports
import argparse
from termcolor import colored
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
	"S:U":1, #Cambiarlo a 0 según fórmula
	"S:C":1, #Cambiarlo a 0 según fórmula
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
cvss=[]
iss= 1-((1-confidenciality)*(1-integrity)*(1-availability))
impact_sc=7.52*(iss-0.029)-3.25*pow((iss-0.02),15)
impact_uc=6.42*iss
exploitability=8.22*av*ac*pr*ui
baseScore=math.ceil((impact+exploitability)*10)/10 #Original formula= math.floor(old_value * 10**ndecimals) / 10**ndecimals

#Definitions
def getCVSS():
	return

def calculateValues():
	return

def createGraph():
	labels = ['']
	impact = [4.2]
	exploitability = [2.5]
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
	ax.text(5,0,str(impact[0]+exploitability[0]), horizontalalignment='center',verticalalignment='center', fontsize=12)
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
	plt.show()

#Argparse

#Main
if __name__ == '__main__':

	getCVSS()
	calculateValues()
	createGraph()