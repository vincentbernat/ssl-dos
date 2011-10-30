#!/usr/bin/env python
# -*- encoding: utf-8 -*-

# Plot data from server-vs-client.

handshakes = 1000
data = [
    ("RSA 1024",     0.991,   1.643),
    ("RSA 2048",     1.129,   6.576),
    ("RSA 4096",     1.524,  37.723),
    ("DH 1024",      6.677,   5.403),
    ("DH 2048",     38.941,  25.546),
    ("DSS 1024",     7.288,   4.254),
    ("DSS 2048",    41.382,  22.200),
    ("ECDH 1024",    4.352,   3.552),
    ("ECDH 2048",    4.477,   8.516),
    ("RSA 1024, e'", 1.062,   1.816),
    ("RSA 2048, e'", 1.311,   8.779),
    ]

from matplotlib.pylab import *
from matplotlib.patches import Ellipse

# Fonts
rcParams['font.family'] = "sans-serif"
rcParams['font.sans-serif'] = ["Droid Sans"]
rcParams['font.size'] = 11

# Create figure
fig = figure(num=None, figsize=(11.69, 8.27), dpi=100)
ax = fig.add_subplot(111)

# Bar plot
pos = (np.arange(len(data))+0.5)[::-1]
client = barh(pos + 0.4, [x[1] for x in data],
              color='#490A3D',
              height=0.4)
server = barh(pos, [x[2] for x in data],
              color='#BD1550',
              height=0.4)

# Write value inside bars
for rect in client + server:
    width = rect.get_width()
    if width > 3:
        xloc = width - 0.3
        color = 'white'
        align = 'right'
    else:
        xloc = width + 0.3
        color = 'black'
        align = 'left'
    yloc = rect.get_y() + rect.get_height()/2.0
    text(xloc, yloc, "%.2f" % width,
         horizontalalignment=align,
         verticalalignment='center',
         color=color, weight='bold')

# Write ratio
for i in range(len(data)):
    width = server[i].get_width()
    if width > 3:
        xloc = width + 2
    else:
        xloc = width + 3.5
    yloc = server[i].get_y() + server[i].get_height()/2.0
    ratio = data[i][2]/data[i][1]
    if ratio <= 2:
        ratio = "%+d %%" % (ratio*100-100)
    else:
        ratio = u"× %.1f" % ratio
    el = Ellipse((xloc, yloc), 3, 0.57, edgecolor="white",
                 facecolor="#8A9B0F", alpha=0.9)
    ax.add_artist(el)
    text(xloc, yloc, ratio,
         horizontalalignment="center",
         verticalalignment='center',
         color="white", weight='bold')

# Axis and legend
yticks(pos + 0.4, [x[0].replace(" ","\n",1) for x in data])
xlabel("CPU time in seconds")
legend(['Client', 'Server'], prop=dict(size=11),
       fancybox=True, shadow=True)


show()
