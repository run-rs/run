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

def plot_rpc():
    global global_hatch_colors
    global global_hatches
    
    y = [
        14.124136,
        24.78197248,
        31.147796,
        39.45007718,
        41.921397,
        48.38327603
    ]

    x = [
        "500",
        "1500",
        "2500",
        "4000",
        "6000",
        "9000",
    ]

    y_pos = np.array(y)
    x_pos = np.array(x)
    fig, ax = plt.subplots(constrained_layout = False)
    ax.plot(x_pos,y_pos,color = '#CA0020', marker='s')
    ax.grid(color='#939393', linestyle=':', linewidth='0.4')
    ax.set_ylim(0)
    ax.set_ylabel('ThroughPut (Gbps)')
    ax.set_xlabel("MTU (bytes)")
    ax.legend()    

    titlefont = {
                    'fontsize': "medium",
                    'fontweight': "bold",
                    'color': "#3B3B3D",
                    'verticalalignment': 'baseline',
                    'horizontalalignment': "center"
                }
    ax.set_title('Rpc with 8MB Response Message',pad = 10, **titlefont)

    # hide the top spines
    ax.spines[['right', 'top']].set_visible(False)

    ax.set_axisbelow(True)

    for tl in ax.get_xticklabels():
        tl.set_fontsize(12)
        tl.set_fontstyle('normal')

    plt.savefig("./figures/rpc" + '.png', dpi = 300)
    plt.savefig("./figures/rpc" + '.pdf', dpi = 300)
    plt.savefig("./figures/rpc" + '.svg', dpi = 300)
    plt.savefig("./figures/rpc" + '.jpg', dpi = 300)

 

if __name__ == "__main__":
    plot_rpc()