#!/usr/bin/env python3

import pandas as pd
import xml.etree.ElementTree as et
from pprint import pprint
import datetime
import argparse
import progressbar

parser = argparse.ArgumentParser(description='Parse an nmap .xml file to CSV', allow_abbrev=False)
parser.add_argument('input', type=str, metavar="INPUT.xml", nargs="+", help="Location of the file(s) to anonymize")
parser.add_argument('--output', "-o", type=str, metavar="OUTPUT.xlsx", help="Location of the output file")
parser.add_argument('--consolidate-ports', "-c", action="store_true", required=False, help="Consolidate open ports into a single field")
args = parser.parse_args()

outfile = args.output
if not outfile:
    outfile = "{}".format(args.input[0].replace(".xml",".xlsx"))
print("Output will go to: {}".format(outfile))


# initilize progress bar
widgets = [ progressbar.Percentage(), progressbar.Bar()]

filecount = len(args.input)
currentfile = 0;
# set headers / existing fields of the dataset
cols = ["host", "timestamp", "time" ]
ports = []
scripts = []
rows = []
totalhosts=0
for f in args.input:
    # read in the xml
    xtree = et.parse(f) #<- input xml here
    xroot = xtree.getroot()

    hosts = xroot.findall('host')
    totalhosts=totalhosts+len(hosts);
bar = progressbar.ProgressBar(max_value = totalhosts, widgets = widgets).start()

i = 0;
for f in args.input:
    # read in the xml
    xtree = et.parse(f) #<- input xml here
    xroot = xtree.getroot()

    hosts = xroot.findall('host')
    hostcount=len(hosts);
    for host in hosts:
        s_starttime = host.attrib.get("starttime")
        s_time = datetime.datetime.fromtimestamp(int(s_starttime)).strftime('%Y-%m-%d %H:%M:%S %Z')
        s_host = host.find("address").attrib.get("addr")

        # example script tags look like:
        # <script id="http-vuln-cve2021-26855_patched" output="Patched against CVE-2021-26855"/>
        # <script id="http-vuln-exchange_v2" output="(15.0.1497) Exchange 2013 potentially vulnerable, check # latest security update is applied (15.0.1497 Exchange 2013 CU23 installed)"/></port>

        row = {"host": s_host, "timestamp": s_starttime, "time": s_time}
        # Iterate over the ports
        open_ports = []
        for port in host.find("ports").findall("port"):
            port_string = "{}/{}".format(port.attrib.get("portid"),port.attrib.get("protocol"))
            if not port_string in ports:
                if port.find('state').attrib.get("state") == "open":
                    open_ports.append(port_string)
            if args.consolidate_ports :
                if port_string not in open_ports:
                    open_ports.append(port_string)
            else :
                row[port_string] = port.find('state').attrib.get("state")
            # check if script tags exist for this host/port, if they do loop over them and add their scriptname : output to the row
            for script in port.findall("script"):
                script_id = script.attrib.get("id")
                if script_id not in scripts:
                    scripts.append(script_id)
                row[script_id] = script.attrib.get("output")
        
        if args.consolidate_ports:
            row["open_ports"] = ", ".join(open_ports)
        rows.append(row)
        i = i + 1
        bar.update(i)
bar.update(totalhosts)
    
print("\nWriting output, this may take a while for large files...")
# prep the out dataframe and write to xlsx
if args.consolidate_ports:
    out_df = pd.DataFrame(rows, columns = cols + ["open_ports"] + scripts)
else:
    out_df = pd.DataFrame(rows, columns = cols + ports + scripts)
out_df.to_excel(outfile, index = False ) 
bar.finish()
pprint(out_df)
print("Done")