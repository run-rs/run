#!/bin/python3
import matplotlib.pyplot as plt
import numpy as np
import math
import csv


Colors = [
    "#C1CFE5",
    "#FEE0C9",
    "#FFF0CC",
]

EdgeColors = [
    "#6095BE",
    "#F47A2A",
    "#FFC432"
]

PacketSize = [64,128,256,512]
CoreNum = [1,2,4,14]

TESTPMD = [[
    [0.0,0.0,0.0,0.0], # bps
    [0,0,0,0], # pps
    [0,0,0,0], # count
],
[
    [0.0,0.0,0.0,0.0], # bps
    [0,0,0,0], # pps
    [0,0,0,0], # count
],
[
    [0.0,0.0,0.0,0.0], # bps
    [0,0,0,0], # pps
    [0,0,0,0], # count
],
[
    [0.0,0.0,0.0,0.0], # bps
    [0,0,0,0], # pps
    [0,0,0,0], # count
]
]

MOONGEN = [[
    [0.0,0.0,0.0,0.0], # bps
    [0,0,0,0], # pps
    [0,0,0,0], # count
],
[
    [0.0,0.0,0.0,0.0], # bps
    [0,0,0,0], # pps
    [0,0,0,0], # count
],
[
    [0.0,0.0,0.0,0.0], # bps
    [0,0,0,0], # pps
    [0,0,0,0], # count
],
[
    [0.0,0.0,0.0,0.0], # bps
    [0,0,0,0], # pps
    [0,0,0,0], # count
]
]

RUN = [[
    [0.0,0.0,0.0,0.0], # bps
    [0,0,0,0], # pps
    [0,0,0,0], # count
],
[
    [0.0,0.0,0.0,0.0], # bps
    [0,0,0,0], # pps
    [0,0,0,0], # count
],
[
    [0.0,0.0,0.0,0.0], # bps
    [0,0,0,0], # pps
    [0,0,0,0], # count
],
[
    [0.0,0.0,0.0,0.0], # bps
    [0,0,0,0], # pps
    [0,0,0,0], # count
]
]

with open("./data/traffic_gen.csv") as csvfile:
    reader = csv.DictReader(csvfile)
    for row in reader:
        idx = int(math.log2(int(row["packet size"])) - 6)
        core = int(row["core number"])
        core_id = 0
        if core == 2 :
            core_id = 1
        if core == 4 :
            core_id = 2
        if core == 14:
            core_id = 3
        if row["generator"] == "Testpmd":
            TESTPMD[core_id][0][idx] += float(row["throughput"])
            TESTPMD[core_id][1][idx] += int(row["packet per seconds"])
            TESTPMD[core_id][2][idx] += 1
        elif row["generator"] == "Moongen":
            MOONGEN[core_id][0][idx] += float(row["throughput"])
            MOONGEN[core_id][1][idx] += int(row["packet per seconds"])
            MOONGEN[core_id][2][idx] += 1
        elif row["generator"] == "RUN":
            RUN[core_id][0][idx] += float(row["throughput"])
            RUN[core_id][1][idx] += int(row["packet per seconds"])
            RUN[core_id][2][idx] += 1

# print(MOONGEN)
# print(RUN)
# print(TESTPMD)

def plot_subplot(plt,subplot,PacketSize):
    global TESTPMD
    global MOONGEN
    global RUN
    global Colors
    global EdgeColors

    idx = subplot - 1
    testpmd = [[0.0,0],[0.0,0],[0.0,0],[0.0,0]]
    moongen = [[0.0,0],[0.0,0],[0.0,0],[0.0,0]]
    run = [[0.0,0],[0.0,0],[0.0,0],[0.0,0]]

    for i in range(4):
        testpmd[i][0] = TESTPMD[i][0][idx] / TESTPMD[i][2][idx]
        testpmd[i][1] = TESTPMD[i][1][idx] / TESTPMD[i][2][idx]
        moongen[i][0] = MOONGEN[i][0][idx] / MOONGEN[i][2][idx]
        moongen[i][1] = MOONGEN[i][1][idx] / MOONGEN[i][2][idx]
        run[i][0] = RUN[i][0][idx] / RUN[i][2][idx]
        run[i][1] = RUN[i][1][idx] / RUN[i][2][idx]

    print(testpmd)
    print(moongen)
    print(run)

    x = np.array(CoreNum)

    width = 0.8
    barSpace = 0.4
    groupSpace = 0.6
    x_pos = []
    for i in range(4):
        pos = i * (4 + groupSpace) + groupSpace
        x_pos.append(pos)
    x_pos = np.array(x_pos)

    bars = {
        "MOONGEN":[moongen[0][0],moongen[1][0],moongen[2][0],moongen[3][0]],
        "TESTPMD":[testpmd[0][0],testpmd[1][0],testpmd[2][0],testpmd[3][0]],
        "RUN":[run[0][0],run[1][0],run[2][0],run[3][0]],
    }

    lines = {
        "MOONGEN":[moongen[0][1],moongen[1][1],moongen[2][1],moongen[3][1]],
        "TESTPMD":[testpmd[0][1],testpmd[1][1],testpmd[2][1],testpmd[3][1]],
        "RUN":[run[0][1],run[1][1],run[2][1],run[3][1]],
    }

    plt.subplot(2,2,subplot)
    multiplier = 0


    for name,value in bars.items():
        offset = (width + barSpace) * multiplier
        x = x_pos + offset
        rects = plt.bar(x, value, width,
                        label = name,
                        color = Colors[multiplier],
                        edgecolor = EdgeColors[multiplier],
                        lw = 0.5,
                        align = 'center')
        multiplier += 1
    plt.xticks(x_pos+1,["1","2","4","12"],fontsize = 14)
    plt.yticks(fontsize = 8)
    plt.xlabel("Core Number (%d Bytes)"%(PacketSize),fontsize = 14)
    plt.ylabel("Throughput (Gbps)",fontsize = 14)
    plt.legend(fontsize=7)
    # plt.title("Packet Size %d Bytes"%(PacketSize),fontsize = 8)



plt.figure(figsize=(10,8))
plot_subplot(plt,1,64)
plot_subplot(plt,2,128)
plot_subplot(plt,3,256)
plot_subplot(plt,4,512)




plt.savefig("./figures/traffic_gen" + '.png', dpi = 500)
plt.savefig("./figures/traffic_gen" + '.pdf', dpi = 500)
plt.savefig("./figures/traffic_gen" + '.svg', dpi = 500)
plt.savefig("./figures/traffic_gen" + '.jpg', dpi = 500)


