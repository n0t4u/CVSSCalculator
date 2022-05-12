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

#Definitions
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

#Main

if __name__ == '__main__':

	getCVSS()
	createGraph()