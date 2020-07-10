#!/usr/bin/env python

"""
Byte histogram over all file
-------------------------------------------
abs_fpath:      Absolute file path - File to load and analyse
fname:          Filename

no_zero bool:   Remove 0x00 from the graph, sometimes this blows other results due to there being numerous amounts - also see log
width int:      Sample width
g_log bool:     Whether to apply a log scale to occurance axis
no_order bool:  Remove the ordered histogram - it shows overall distribution
"""

from __future__ import division

from __future__ import absolute_import
import os
import sys
import numpy as np
import matplotlib

matplotlib.use("Agg")
import matplotlib.ticker as ticker
import matplotlib.pyplot as plt
from matplotlib.ticker import MaxNLocator
from collections import Counter

import logging

log = logging.getLogger("graph.hist")

# # Graph defaults
__no_zero__ = False
__width__ = 1
__g_log__ = True
__no_order__ = False
__colours__ = ["#ff01d5", "#01ff2b"]

# Set args in args parse
def args_setup(arg_parser):

    arg_parser.add_argument(
        "--no_zero",
        action="store_true",
        default=__no_zero__,
        help="Remove 0x00 from the graph, sometimes this blows other results due to there being numerous amounts - also see --no_log",
    )
    arg_parser.add_argument("--width", type=int, default=__width__, metavar=__width__, help="Sample width")
    arg_parser.add_argument("--no_log", action="store_false", default=__g_log__, help="Do _not_ apply a log scale to occurance axis")
    arg_parser.add_argument(
        "--no_order", action="store_true", default=__no_order__, help="Remove the ordered histogram - It shows overall distribution when on"
    )
    arg_parser.add_argument(
        "--colours", type=str, nargs=2, default=__colours__, metavar="#ff01d5", help="Colours for the graph. First value is the ordered graph"
    )


# Validate graph specific arguments
class ArgValidationEx(Exception):
    pass


def args_validation(args):

    # # Test to see what matplotlib backend is setup
    backend = matplotlib.get_backend()
    if not backend == "TkAgg":
        log.warning('{} matplotlib backend in use. This graph generation was tested with "TkAgg", bugs may lie ahead...'.format(backend))

    # # Test to see if we should use defaults
    if args.graphtype == "all":
        args.no_zero = __no_zero__
        args.width = __width__
        args.no_log = __g_log__
        args.no_order = __no_order__
        args.colours = __colours__

    try:
        args.colours[0] = matplotlib.colors.to_rgba(args.colours[0])
        args.colours[1] = matplotlib.colors.to_rgba(args.colours[1])
    except ValueError as e:
        raise ArgValidationEx("Error parsing --colours: {}".format(e))


def generate(abs_fpath, fname, no_zero=__no_zero__, width=__width__, g_log=__g_log__, no_order=__no_order__, colours=__colours__, **kwargs):

    file_array = []
    with open(abs_fpath, "rb") as fh:
        for x in bytearray(fh.read()):
            file_array.append(x)

    log.debug('Read: "{}", length: {}'.format(fname, len(file_array)))

    log.debug("Ignore 0's: {}".format(no_zero))
    no_zero = -int(no_zero)

    fig, ax = plt.subplots()

    # # Add a byte hist ordered 1 > 255
    ordered_row = []
    c = Counter(file_array)
    for x in range(no_zero, 256):
        ordered_row.append(c[x])

    ax.bar(
        np.array(list(range(no_zero, 256))),
        np.array(ordered_row),
        align="edge",
        width=width,
        label="Bytes",
        color=colours[0],
        log=g_log,
        zorder=0,
        linewidth=0,
    )
    log.debug("Graphed binary array")

    # # Add a byte hist ordered by occurrence - shows general distribution
    if not no_order:
        sorted_row = []
        c = Counter(file_array)
        for x in range(no_zero, 256):
            sorted_row.append(c[x])

        sorted_row.sort()
        sorted_row.reverse()

        ax.bar(
            np.array(list(range(no_zero, 256))),
            np.array(sorted_row),
            width=width,
            label="Ordered",
            color=colours[1],
            log=g_log,
            zorder=1,
            alpha=0.5,
            linewidth=0,
        )
        log.debug("Graphed ordered binary array")

    # # Formatting and watermarking
    ax.xaxis.set_major_formatter(ticker.FuncFormatter(lambda x, pos: ("0x{:02X}".format(int(x)))))
    ax.xaxis.set_major_locator(MaxNLocator(20))
    ax.set_xlabel(
        "Bytes (0x00 included: {}, {})".format((True if no_zero == 0 else False), ("width 1" if width == 1 else "width: " + str(width)))
    )
    ax.set_ylabel("Occurrence (log {})".format(g_log))

    # Include 0x00 byte?
    if no_zero:
        ax.set_xlim(1, 255)
        ax.set_xbound(lower=1, upper=255)
        log.debug("Ignoring 0x00, setting xlim/xbounds to (1,255)")
    else:
        ax.set_xlim(0, 255)
        ax.set_xbound(lower=0, upper=255)
        log.debug("Setting xlim/xbounds to (0,255)")

    plt.legend(loc="upper center", ncol=3, bbox_to_anchor=(0.5, 1.07), framealpha=1)

    plt.title("Byte histogram: {}\n".format(fname))

    return plt, {}, {}


if __name__ == "__main__":

    import argparse, sys

    logging.basicConfig(stream=sys.stderr, format="%(levelname)s | %(message)s", level=logging.DEBUG)
    logging.getLogger("matplotlib").setLevel(logging.CRITICAL)
    log = logging.getLogger("hist")

    # ## Global graphing default values
    __figformat__ = "png"  # Output format of saved figure
    __figsize__ = (12, 4)  # Size of figure in inches
    __figdpi__ = 100  # DPI of figure
    __showplt__ = False  # Show the plot interactively
    __blob__ = False  # Treat all files as binary blobs. Disable intelligently parsing of file format specific features.

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-f",
        "--file",
        type=str,
        required=True,
        metavar="malware.exe",
        help="Give me a graph of this file. See - if this is the only argument specified.",
    )
    parser.add_argument("--showplt", action="store_true", default=__showplt__, help="Show plot interactively (disables saving to file)")
    parser.add_argument(
        "--format",
        type=str,
        default=__figformat__,
        choices=["png", "pdf", "ps", "eps", "svg"],
        required=False,
        metavar="png",
        help="Graph output format",
    )
    parser.add_argument("--figsize", type=int, nargs=2, default=__figsize__, metavar="#", help="Figure width and height in inches")
    parser.add_argument("--dpi", type=int, default=__figdpi__, metavar=__figdpi__, help="Figure dpi")
    parser.add_argument(
        "--blob",
        action="store_true",
        default=__blob__,
        help="Do not intelligently parse certain file types. Treat all files as a binary blob. E.g. don't add PE entry point or section splitter to the graph",
    )

    args_setup(parser)

    args = parser.parse_args()

    args.graphtype = __name__

    args_validation(args)

    args_dict = args.__dict__
    args_dict["abs_fpath"] = args.file
    args_dict["fname"] = os.path.basename(args.file)
    args_dict["abs_save_fpath"] = "{}.{}".format(os.path.basename(args_dict["abs_fpath"]), args.format)

    plt, save_kwargs, json_data = generate(**args_dict)

    fig = plt.gcf()
    fig.set_size_inches(*args.figsize, forward=True)

    plt.tight_layout()

    if args.showplt:
        log.debug("Opening graph interactively")
        plt.show()
    else:
        plt.savefig(args_dict["abs_save_fpath"], format=args.format, dpi=args.dpi, forward=True, **save_kwargs)
        log.info('Graph saved to: "{}"'.format(args_dict["abs_save_fpath"]))
