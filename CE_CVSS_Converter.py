import argparse
import xml.etree.ElementTree as ET
from cvss import CVSS3

csvHeaders = ['CVSS Score', 'IP', 'FQDN', 'OS', 'Port', 'Vulnerability', 'Description', 'Proof', 'Solution', 'See Also', 'CVE', 'CVSS_Vector', 'cvss3_base_score']
nessusFields = ['cvss_base_score', 'host-ip', 'host-fqdn', 'operating-system', 'port', 'plugin_name', 'description', 'plugin_output', 'solution', 'see_also', 'cve', 'cvss_vector', 'cvss3_base_score']
FailList = []
ActionPointList = []
# Clean values from nessus report
def getValue(rawValue):
	cleanValue = rawValue.replace('\n', ' ').strip(' ')
	if len(cleanValue) > 32000:
		cleanValue = cleanValue[:32000] + ' [Text Cut Due To Length]'
	return cleanValue

# Helper function for handleReport()
def getKey(rawKey):
	return csvHeaders[nessusFields.index(rawKey)]

# Handle a single report item
def handleReport(report):
	findings = []

	reportHost = dict.fromkeys(csvHeaders, '')
	for item in report:
		flag = False
		if item.tag == 'HostProperties':
			for tag in (tag for tag in item if tag.attrib['name'] in nessusFields):
				reportHost[getKey(tag.attrib['name'])] = getValue(tag.text)
		if item.tag == 'ReportItem':
			reportRow = dict(reportHost)
			reportRow['Port'] = item.attrib['port']
			reportRow['Vulnerability'] = item.attrib['pluginName']
			for tag in (tag for tag in item if tag.tag in nessusFields):
				reportRow[getKey(tag.tag)] = getValue(tag.text)
				if tag.tag == 'cvss3_base_score':
					if float(tag.text) > 6.9:
						FailList.append(reportRow['Vulnerability'] + "\t\t\tScore: "+ tag.text + "\t\tHost: " + reportRow['IP'])
					if float(tag.text) < 6.9 and float(tag.text) > 4.0:
						ActionPointList.append(reportRow['Vulnerability']  + "\t\t\tScore: "+ tag.text + "\t\tHost: " + reportRow['IP'])
					flag = True
				if tag.tag == 'cvss_vector' and flag == False:	
					item1 = ET.SubElement(item, 'cvss3_base_score')
					item1.text=str(CVSSConvert(tag.text))

					if CVSSConvert(tag.text) > 6.9:
						FailList.append(reportRow['Vulnerability'] + "\t\t\tScore: "+ str(CVSSConvert(tag.text)) + "\t\tHost: " + reportRow['IP'])
					if CVSSConvert(tag.text) < 6.9 and CVSSConvert(tag.text) > 4.0:
						ActionPointList.append(reportRow['Vulnerability']  + "\t\t\tScore: "+ str(CVSSConvert(tag.text)) + "\t\tHost: " + reportRow['IP'])

			# Clean up - Mike G
			if reportRow['CVSS Score'] != "":
			   findings.append(reportRow)
	return findings


def CVSSConvert(cssvector):
	convertedVector = cssvector.replace("CVSS2#","CVSS:3.0/")
	convertedVector = convertedVector.replace("AV:L","AV:N")
	convertedVector = convertedVector.replace("AV:A","AV:N")
	convertedVector = convertedVector.replace("AC:M","AC:L")
	convertedVector = convertedVector.replace("AC:H","AC:L")
	convertedVector = convertedVector.replace("Au:S","PR:N")
	convertedVector = convertedVector.replace("Au:M","PR:N")
	convertedVector = convertedVector.replace("Au:N","PR:N")
	convertedVector = convertedVector.replace(":P",":L")
	convertedVector = convertedVector.replace(":C",":H")
	convertedVector = convertedVector + "/UI:N/E:F/RC:C/S:U"

	c = CVSS3(convertedVector)
	return c.scores()[0]


# Get files 
def handleArgs():
	aparser = argparse.ArgumentParser(description='CEPLUS Nessus Interpreter.', usage="\npython3 CE_CVSS_Converter.py input.nessus")
	aparser.add_argument('nessus_xml_files', type=str, nargs='+', help="nessus xml file to parse")
	args = aparser.parse_args()
	return args.nessus_xml_files

if __name__ == '__main__':
	for nessusScan in handleArgs():
		try:
			scanfile = ET.parse(nessusScan)
		except IOError:
			print("Can't find file: " + nessusScan)
			exit()
		xmlRoot = scanfile.getroot()
		for report in xmlRoot.findall('./Report/ReportHost'):
			findings = handleReport(report)
			# print(findings)
	scanfile.write('CVSSv3_nessusScan')

	print("\033[1;31;40m--------------------FAIL---------------------")
	for item in FailList:
		print(item)
	print("\n\n\n\033[1;33;40m-----------------ACTIONPOINT-----------------")
	for item in ActionPointList:
		print(item)


