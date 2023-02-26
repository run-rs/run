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

def plot_tcp_csum():
    global global_hatch_colors
    global global_hatches
    
    bargroup = ["128","256","512","1518"]
    bars = {
        "Pbuf":[0,0,0,0],
        "Cursor":[0,0,0,0],
        "SmolTcp":[0,0,0,0],
        "Pnet":[0,0,0,0],
    }
    
    with open("./data/tcp_csum.csv", newline = '') as csvfile:
        reader = csv.DictReader(csvfile)
        pbuf = {
            "128":[0,0],
            "256":[0,0],
            "512":[0,0],
            "1518":[0,0]
        }
        cursor = {
            "128":[0,0],
            "256":[0,0],
            "512":[0,0],
            "1518":[0,0]
        }
        smoltcp = {
            "128":[0,0],
            "256":[0,0],
            "512":[0,0],
            "1518":[0,0]
        }
        pnet = {
            "128":[0,0],
            "256":[0,0],
            "512":[0,0],
            "1518":[0,0]
        }
        for row in reader:
            if row["framework"] == "Pbuf":
                pbuf[row["mtu"]][0] += float(row["throughput"])
                pbuf[row["mtu"]][1] += 1
            if row["framework"] == "Cursor":
                cursor[row["mtu"]][0] += float(row["throughput"])
                cursor[row["mtu"]][1] += 1
            if row["framework"] == "SmolTcp":
                smoltcp[row["mtu"]][0] += float(row["throughput"])
                smoltcp[row["mtu"]][1] += 1
            if row["framework"] == "Pnet":
                pnet[row["mtu"]][0] += float(row["throughput"])
                pnet[row["mtu"]][1] += 1
        
        bars["Pbuf"][0] = pbuf["128"][0] / pbuf["128"][1]
        bars["Pbuf"][1] = pbuf["256"][0] / pbuf["256"][1]
        bars["Pbuf"][2] = pbuf["512"][0] / pbuf["512"][1]
        bars["Pbuf"][3] = pbuf["1518"][0] / pbuf["1518"][1]
        
        bars["Cursor"][0] = cursor["128"][0] / cursor["128"][1]
        bars["Cursor"][1] = cursor["256"][0] / cursor["256"][1]
        bars["Cursor"][2] = cursor["512"][0] / cursor["512"][1]
        bars["Cursor"][3] = cursor["1518"][0] / cursor["1518"][1]
        
        bars["SmolTcp"][0] = smoltcp["128"][0] / smoltcp["128"][1]
        bars["SmolTcp"][1] = smoltcp["256"][0] / smoltcp["256"][1]
        bars["SmolTcp"][2] = smoltcp["512"][0] / smoltcp["512"][1]
        bars["SmolTcp"][3] = smoltcp["1518"][0] / smoltcp["1518"][1]
        
        bars["Pnet"][0] = pnet["128"][0] / pnet["128"][1]
        bars["Pnet"][1] = pnet["256"][0] / pnet["256"][1]
        bars["Pnet"][2] = pnet["512"][0] / pnet["512"][1]
        bars["Pnet"][3] = pnet["1518"][0] / pnet["1518"][1]
        
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
                    yerr = error,
                    edgecolor = hatch_colors[name],
                    lw = 1,
                    align = 'center',
                    hatch = hatches[name])
        if name == "Pbuf":
            ax.bar_label(rects,fmt="%.2f",color='b',fontsize=8,padding=4)
        if name == "SmolTcp":
            ax.bar_label(rects,fmt="%.2f",color='b',fontsize=8,padding=16)
        if name == "Cursor":
            ax.bar_label(rects,fmt="%.2f",color='b',fontsize=8,padding=1)
        if name == "Pnet":
            ax.bar_label(rects,fmt="%.2f",color='b',fontsize=8,padding=1)

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
    ax.set_title('Tcp Protocol Stack Performance with Checksum Offload',pad = 10, **titlefont)

    # hide the top spines
    ax.spines[['right', 'top']].set_visible(False)

    ax.set_xticks(x_pos + width, bargroup)
    ax.legend(loc='upper left', ncols = 1)

    for tl in ax.get_xticklabels():
        tl.set_fontsize(12)
        tl.set_fontstyle('normal')

    plt.savefig("./figures/tcp_csum" + '.png', dpi = 300)
    plt.savefig("./figures/tcp_csum" + '.pdf', dpi = 300)
    plt.savefig("./figures/tcp_csum" + '.svg', dpi = 300)
    plt.savefig("./figures/tcp_csum" + '.jpg', dpi = 300)
 
def plot_tcp():
    global global_hatch_colors
    global global_hatches
    
    bargroup = ["128","256","512","1518"]
    bars = {
        "Pbuf":[0,0,0,0],
        "Cursor":[0,0,0,0],
        "SmolTcp":[0,0,0,0],
        "Pnet":[0,0,0,0],
    }
    
    with open("./data/tcp.csv", newline = '') as csvfile:
        reader = csv.DictReader(csvfile)
        pbuf = {
            "128":[0,0],
            "256":[0,0],
            "512":[0,0],
            "1518":[0,0]
        }
        cursor = {
            "128":[0,0],
            "256":[0,0],
            "512":[0,0],
            "1518":[0,0]
        }
        smoltcp = {
            "128":[0,0],
            "256":[0,0],
            "512":[0,0],
            "1518":[0,0]
        }
        pnet = {
            "128":[0,0],
            "256":[0,0],
            "512":[0,0],
            "1518":[0,0]
        }
        for row in reader:
            if row["framework"] == "Pbuf":
                pbuf[row["mtu"]][0] += float(row["throughput"])
                pbuf[row["mtu"]][1] += 1
            if row["framework"] == "Cursor":
                cursor[row["mtu"]][0] += float(row["throughput"])
                cursor[row["mtu"]][1] += 1
            if row["framework"] == "SmolTcp":
                smoltcp[row["mtu"]][0] += float(row["throughput"])
                smoltcp[row["mtu"]][1] += 1
            if row["framework"] == "Pnet":
                pnet[row["mtu"]][0] += float(row["throughput"])
                pnet[row["mtu"]][1] += 1
        
        bars["Pbuf"][0] = pbuf["128"][0] / pbuf["128"][1]
        bars["Pbuf"][1] = pbuf["256"][0] / pbuf["256"][1]
        bars["Pbuf"][2] = pbuf["512"][0] / pbuf["512"][1]
        bars["Pbuf"][3] = pbuf["1518"][0] / pbuf["1518"][1]
        
        bars["Cursor"][0] = cursor["128"][0] / cursor["128"][1]
        bars["Cursor"][1] = cursor["256"][0] / cursor["256"][1]
        bars["Cursor"][2] = cursor["512"][0] / cursor["512"][1]
        bars["Cursor"][3] = cursor["1518"][0] / cursor["1518"][1]
        
        bars["SmolTcp"][0] = smoltcp["128"][0] / smoltcp["128"][1]
        bars["SmolTcp"][1] = smoltcp["256"][0] / smoltcp["256"][1]
        bars["SmolTcp"][2] = smoltcp["512"][0] / smoltcp["512"][1]
        bars["SmolTcp"][3] = smoltcp["1518"][0] / smoltcp["1518"][1]
        
        bars["Pnet"][0] = pnet["128"][0] / pnet["128"][1]
        bars["Pnet"][1] = pnet["256"][0] / pnet["256"][1]
        bars["Pnet"][2] = pnet["512"][0] / pnet["512"][1]
        bars["Pnet"][3] = pnet["1518"][0] / pnet["1518"][1]
        
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
                    yerr = error,
                    edgecolor = hatch_colors[name],
                    lw = 1,
                    align = 'center',
                    hatch = hatches[name])
        if name == "Pbuf":
            ax.bar_label(rects,fmt="%.2f",color='b',fontsize=8,padding=4)
        if name == "SmolTcp":
            ax.bar_label(rects,fmt="%.2f",color='b',fontsize=8,padding=16)
        if name == "Cursor":
            ax.bar_label(rects,fmt="%.2f",color='b',fontsize=8,padding=1)
        if name == "Pnet":
            ax.bar_label(rects,fmt="%.2f",color='b',fontsize=8,padding=1)

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
    ax.set_title('Tcp Protocol Stack Performance without Checksum Offload',pad = 10, **titlefont)

    # hide the top spines
    ax.spines[['right', 'top']].set_visible(False)

    ax.set_xticks(x_pos + width, bargroup)
    ax.legend(loc='upper left', ncols = 1)

    for tl in ax.get_xticklabels():
        tl.set_fontsize(12)
        tl.set_fontstyle('normal')

    plt.savefig("./figures/tcp" + '.png', dpi = 300)
    plt.savefig("./figures/tcp" + '.pdf', dpi = 300)
    plt.savefig("./figures/tcp" + '.svg', dpi = 300)
    plt.savefig("./figures/tcp" + '.jpg', dpi = 300)
    
if __name__ == "__main__":
    plot_tcp()
    plot_tcp_csum()