#!/bin/python3

import os
import argparse
import csv

import numpy as np
import matplotlib.pyplot as plt

global_hatches = [
    '////',
    '\\\\\\\\',
    '|||||',
    '----',
    'xxxx',
    '++++',
    'o-',
    '\|',
    '..',
    '*',
    '',
    '|*',
    '-\\',
]

global_hatch_colors = [
    "#969696",
    "#FED966",
    "#8CB3D7",
    "#FFFFFF",
    "#DBDBDB",
    "#FFFFFF",
    "#969696",
    "#DBDBDB",
    "#FFFFFF",
    "#969696",
    "#DBDBDB",
    "#FFFFFF",
    "#969696",
    "#DBDBDB",
    "#FFFFFF",
]


def main():
    global global_hatch_colors
    global global_hatches
    
    bargroup = ["256","512","1518"]
    bars = {
        "normal":[3.6732,7.8438,20.3011],
        "enable tso":[0,0,0],
    }
    
    with open("./data/tso.csv", newline = '') as csvfile:
        reader = csv.DictReader(csvfile)
        tso = {
            "256":[0,0],
            "512":[0,0],
            "1518":[0,0]
        }
        
        for row in reader:
            tso[row["mtu"]][0] += float(row["throughput"])
            tso[row["mtu"]][1] += 1
        
        bars["enable tso"][0] = tso["256"][0] / tso["256"][1]
        bars["enable tso"][1] = tso["512"][0] / tso["512"][1]
        bars["enable tso"][2] = tso["1518"][0] / tso["1518"][1]
       
        print(bars)
    
        
    hatches = {}
    hatch_colors = {}

    i = 0
    for name in bars:
        hatches[name] = global_hatches[i]
        hatch_colors[name] = global_hatch_colors[i]
        i += 1

    width = 0.4
    barSpace = 0.08
    groupSpace = 0.6
    group_len = len(bars) * width + barSpace * (len(bars) - 1)
    x_pos = []
    for i in range(len(bargroup)):
        pos = i * (group_len + groupSpace) + groupSpace
        x_pos.append(pos)
    print(x_pos)
    x_pos = np.array(x_pos)
    multiplier = 0

    fig, ax = plt.subplots(constrained_layout = False)
    for name, value in bars.items():
        print(name)
        offset = (width + barSpace) * multiplier
        x = x_pos + offset
        print(x)
        print(value)
        error = np.random.rand(len(bars))
        rects = ax.bar(x, value, width,
                    label = name,
                    color = None,
                    #yerr = error,
                    edgecolor = hatch_colors[name],
                    lw = 1,
                    align = 'center',
                    hatch = hatches[name])
        ax.bar_label(rects,fmt="%0.2f",color='b')
        multiplier += 1
    

    ax.set_ylabel('ThroughPut (Gbps)')
    ax.set_xlabel("MTU")
    ax.set_ylim(0)
    

    titlefont = {
                    'fontsize': "medium",
                    'fontweight': "bold",
                    'color': "#3B3B3D",
                    'verticalalignment': 'baseline',
                    'horizontalalignment': "center"
                }
    ax.set_title('Tcp Protocol Stack Performance',pad = 10, **titlefont)

    # hide the top spines
    ax.spines[['right', 'top']].set_visible(False)

    ax.set_xticks(x_pos + width, bargroup)
    ax.legend(loc='upper left', ncols = 1)

    for tl in ax.get_xticklabels():
        tl.set_fontsize(12)
        tl.set_fontstyle('normal')

    plt.savefig("./figures/tso" + '.png', dpi = 300)
    plt.savefig("./figures/tso" + '.pdf', dpi = 300)
    plt.savefig("./figures/tso" + '.svg', dpi = 300)
    plt.savefig("./figures/tso" + '.jpg', dpi = 300)
    
if __name__ == "__main__":
    main()