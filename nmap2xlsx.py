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
args = parser.parse_args()

outfile = args.output
if not outfile:
    outfile = "{}".format(args.input[0].replace(".xml",".xlsx"))
print("Output will go to: {}".format(outfile))


# initilize progress bar
widgets = [ progressbar.Percentage(), progressbar.Bar()]

filecount = len(args.input)
currentfile = 0;
bar = progressbar.ProgressBar(max_value = filecount+1, widgets = widgets).start()
# set headers / existing fields of the dataset
cols = ["host", "timestamp", "time" ]
ports = []
scripts = []
rows = []
for f in args.input:
    # read in the xml
    xtree = et.parse(f) #<- input xml here
    xroot = xtree.getroot()

    hosts = xroot.findall('host')
    hostcount=len(hosts);
    i = 0;
    for host in hosts:
        s_starttime = host.attrib.get("starttime")
        s_time = datetime.datetime.fromtimestamp(int(s_starttime)).strftime('%Y-%m-%d %H:%M:%S %Z')
        s_host = host.find("address").attrib.get("addr")

        # example script tags look like:
        # <script id="http-vuln-cve2021-26855_patched" output="Patched against CVE-2021-26855"/>
        # <script id="http-vuln-exchange_v2" output="(15.0.1497) Exchange 2013 potentially vulnerable, check # latest security update is applied (15.0.1497 Exchange 2013 CU23 installed)"/></port>

        row = {"host": s_host, "timestamp": s_starttime, "time": s_time}
        # Iterate over the ports
        for port in host.find("ports").findall("port"):
            port_string = "{}/{}".format(port.attrib.get("portid"),port.attrib.get("protocol"))
            if not port_string in ports:
                ports.append(port_string)
            row[port_string] = port.find('state').attrib.get("state")
            # check if script tags exist for this host/port, if they do loop over them and add their scriptname : output to the row
            for script in port.findall("script"):
                script_id = script.attrib.get("id")
                if script_id not in scripts:
                    scripts.append(script_id)
                row[script_id] = script.attrib.get("output")

        rows.append(row)
        i = i + 1
        bar.update(currentfile+(i/hostcount))
    currentfile=currentfile+1
    bar.update(currentfile)
    

# prep the out dataframe and write to xlsx
out_df = pd.DataFrame(rows, columns = cols + ports + scripts)
#out_df.to_csv(r'notNL_rescan_4_parsed.csv', index = False)
out_df.to_excel(outfile, index = False ) # <---- Give output file name here
bar.finish()
pprint(out_df)
