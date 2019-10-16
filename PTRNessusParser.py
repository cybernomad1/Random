# Graph generation from https://github.com/Agent-Tiro/Random/blob/master/stats.py
# Merge Nessus files from https://gist.github.com/mastahyeti/2720173
# Nessus parsing from https://github.com/leebaird/discover/blob/master/parsers/parse-nessus.py

import argparse
import xml.etree.ElementTree as ET
import os
import shutil
import codecs
import csv
from io import StringIO
import pandas as pd
import numpy as np



csvHeaders = ['CCS_REF','CVSS Score','Risk', 'Host', 'OS', 'Port', 'Vulnerability', 'Synopsis', 'Proof', 'Solution', 'See Also', 'CVE']
nessusFields = ['CCS_REF','cvss_base_score','risk_factor','host-fqdn', 'operating-system', 'port', 'plugin_name', 'Synopsis', 'plugin_output', 'solution', 'see_also', 'cve']
count = 1
issues = {}


def NessusMerge(directory):
    first = 1
    print(":: Merging Files")
    for FileName in os.listdir(directory):
        if ".nessus" in FileName:
            print(":: Parsing", directory + "/" + FileName)
            if first:
                mainTree = ET.parse(directory + "/" + FileName)
                report = mainTree.find('Report')
                report.attrib['name'] = 'Merged Report'
                first = 0
            else:
                tree = ET.parse(directory + "/" + FileName)
                for host in tree.findall('.//ReportHost'):
                    existing_host = report.find(".//ReportHost[@name='"+host.attrib['name']+"']")
                    if not existing_host:
                        print(":: Adding host: " + host.attrib['name'])
                        report.append(host)
                    else:
                        for item in host.findall('ReportItem'):
                            if not existing_host.find("ReportItem[@port='"+ item.attrib['port'] +"'][@pluginID='"+ item.attrib['pluginID'] +"']"):
                                print(":: Adding finding: " + item.attrib['port'] + ":" + item.attrib['pluginID'])
                                existing_host.append(item)
            print(":: => done")
    print(":: Merging Complete")    
    
    if "CCS_REF_temp" in os.listdir("."):
        shutil.rmtree("CCS_REF_temp")

    os.mkdir("CCS_REF_temp")
    mainTree.write("CCS_REF_temp/Merged_nessus.nessus", encoding="utf-8", xml_declaration=True)

def addref(projectID):
   
    print(":: Adding CCS Ref")
    #scanfile = ET.parse("CCS_REF_temp/Merged_nessus.nessus")
    scanfile = ET.parse("report.nessus")
    xmlRoot = scanfile.getroot()
    for report in xmlRoot.findall('./Report/ReportHost'):
        handleReport(report,projectID)
    
    print(":: => done")
    print(":: Writing nessus file: " + projectID[0] + "_nessusScan.nessus")
    scanfile.write(projectID[0] + "_nessusScan.nessus")
    print(":: => done")

def CreateStatsExcel(CSV,projectID):
    print(":: Generating Stats")
    #Load csv up with only the relevant columns
    df = pd.read_csv(
        CSV,
        usecols=['CVSS Score', 'Risk', 'Host', 'Vulnerability']
        )
    #Remove all NaN / informational items / and duplicate rows                                            
    df = df.dropna(subset=['CVSS Score'])         
    df = df.drop_duplicates()               

    #only displays rows of that Risk level
    #df = df.loc[(df['Risk'] == 'Critical')] 
    #df = df.loc[(df['Risk'] == 'High')]
    #df = df.loc[(df['Risk'] == 'Medium')]
    df1 = df.loc[(df['CVSS Score'] > 6.9)]

    #Create Excel Writer object
    with pd.ExcelWriter(projectID + "_Stats.xlsx") as writer:

        #Display Hosts with most High and above vulnerabilities
        HostsHighVuln = df1.groupby(['Host'])['Host']\
                .count()\
                .reset_index(name='Number of Vulnerabilities')\
                .sort_values(['Number of Vulnerabilities'], ascending=False)\
                .head(5)

        HostsHighVuln.to_excel(writer,
                sheet_name='Hosts High+ Vuln')

        #Display Hosts with most vulnerabilities
        HostsAllVuln = df.groupby(['Host'])['Host']\
                .count()\
                .reset_index(name='Number of Vulnerabilities')\
                .sort_values(['Number of Vulnerabilities'], ascending=False)\
                .head(5)

        HostsAllVuln.to_excel(writer,
                sheet_name='Hosts All Vuln')

        #Hosts with counts of vulnerabilities by risk
        VulnsByRisk = df.groupby(['Host'])['Risk']\
                .value_counts()

        VulnsByRisk.to_excel(writer,
                sheet_name='VulnsByRisk')

        #Display most common vulnerabilities on the network
        CommonVulns = df.groupby(['Vulnerability'])['Host']\
                .count()\
                .reset_index(name='Affected Hosts')\
                .sort_values(['Affected Hosts'], ascending=False)\
                .head(5)

        CommonVulns.to_excel(writer,
                sheet_name='CommonVulns')

        #Display most common high and above vulnerabilities on the network
        HighCommonVuln = df1.groupby(['Vulnerability'])['Host']\
                .count()\
                .reset_index(name='Affected Hosts')\
                .sort_values(['Affected Hosts'], ascending=False)\
                .head(5)

        HighCommonVuln.to_excel(writer,
                sheet_name='HighCommonVuln')

        #Display total risk (all cvss added together)
        TotalRisk = df.groupby(['Host'])['CVSS Score']\
                .sum()\
                .reset_index(name='Risk Score')\
                .sort_values(['Risk Score'], ascending =False)\
                .head(10)

        TotalRisk.to_excel(writer,
                sheet_name='TotalRisk')

        #Display hosts with most unique vulnerabilities
        df2 = (df.drop_duplicates(subset='Vulnerability'))
        UniqueVulns = df2.groupby(['Host'])['Host']\
                .count()\
                .reset_index(name='Unique Vulnerabilities')\
                .sort_values(['Unique Vulnerabilities'], ascending=False)\
                .head(5)

        UniqueVulns.to_excel(writer,
                sheet_name='UniqueVulns')
    print(":: => done")

def checkdict(issue,projectID):
    global count
    global issues
    if issue in issues.keys():
        return issues[issue]
    else:
        issues[issue] = projectID + "-CCS-" + str(count)
        count = count + 1
        return issues[issue]
    #is value in dict if yes return key
    #if not add issue to dict with count, increment count and return key

def createCSV(projectID,reportRows):
    with open(projectID[0] + '_PSNITHC.csv', 'w') as csvFile:
        writer = csv.DictWriter(csvFile,csvHeaders)
        writer.writeheader()
        writer.writerows(reportRows)

    csvFile.close()    
    

def handleReport(report,projectID):
    Vuln = ""
    for item in report:
        if item.tag == 'ReportItem':
            Vuln = item.attrib['pluginName']
            for tag in (tag for tag in item):
                if tag.tag == 'cvss_base_score':	
                    item1 = ET.SubElement(item, 'CCS_REF')
                    item1.text=checkdict(Vuln,projectID[0])
                      

# Clean values from nessus report
def getValue(rawValue):
    cleanValue = rawValue.replace('\n', ' ').strip(' ')
    if len(cleanValue) > 32000:
        cleanValue = cleanValue[:32000] + ' [Text Cut Due To Length]'
    return cleanValue

# Helper function for handleReport()
def getKey(rawKey):
    return csvHeaders[nessusFields.index(rawKey)]

def handleReportCSV(report):
    findings = []
    reportHost = dict.fromkeys(csvHeaders, '')
    for item in report:
        if item.tag == 'HostProperties':
            for tag in (tag for tag in item if tag.attrib['name'] in nessusFields):
                reportHost[getKey(tag.attrib['name'])] = getValue(tag.text)
        if item.tag == 'ReportItem':
            reportRow = dict(reportHost)
            reportRow['Port'] = item.attrib['port']
            reportRow['Vulnerability'] = item.attrib['pluginName']
            for tag in (tag for tag in item if tag.tag in nessusFields):
                reportRow[getKey(tag.tag)] = getValue(tag.text)
            # Clean up - Mike G
            if reportRow['CVSS Score'] != "":
                findings.append(reportRow)
    return findings

def CreatePSNCSV(projectID):
    print(":: Creating PSN csv")
    reportRows = []
    
    scanFile = ET.parse(projectID[0] + "_nessusScan.nessus")
        
    xmlRoot = scanFile.getroot()
    for report in xmlRoot.findall('./Report/ReportHost'):
        findings = handleReportCSV(report)
        reportRows.extend(findings)
    createCSV(projectID,reportRows)
    print(":: => done")

if __name__ == '__main__':
    
    
    aparser = argparse.ArgumentParser(description='CCS REF Nessus Interpreter.', usage="\npython3 CCS_REF.py input.nessus")
    aparser.add_argument("-d", "--directory", type=str, nargs='+', help="directory containing .nessus files to parse")
    aparser.add_argument("-p", "--projectID", type=str, nargs='+', help="Project ID")
    args = aparser.parse_args()

    if not args.directory:
        aparser.print_help()
        print("\n[-] Please specify an input directory to parse. "
              "Use -d <input.nessus> to specify the file\n")
        exit()
    if not args.projectID:
        aparser.print_help()
        print("\n[-] Please specify a ProjectID\n")

    NessusMerge(args.directory[0])
    addref(args.projectID)
    CreatePSNCSV(args.projectID)
    CreateStatsExcel(args.projectID[0] + '_PSNITHC.csv', args.projectID[0])
    print(":: Cleaning up")
    shutil.rmtree("CCS_REF_temp")
    print(":: All actions completed")

