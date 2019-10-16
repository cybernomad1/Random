import argparse
import xml.etree.ElementTree as ET

def handleArgs():
	aparser = argparse.ArgumentParser(description='Nessus Interpreter.', usage="\n.NessusNameUpdater.py input.nessus")
	aparser.add_argument('nessus_xml_files', type=str, nargs='+', help="nessus xml file to parse")
	args = aparser.parse_args()
	return args.nessus_xml_files

def line_prepender(filename, line):
    with open(filename, 'r+') as f:
        content = f.read()
        f.seek(0, 0)
        f.write(line.rstrip('\r\n') + '\n' + content)

def handleReport(report):
	findings = []
	name = ""
	for Host in report:
		for item in Host:
			if item.tag == 'HostProperties':
				for tag in item:
					if tag.attrib['name'] == "host-rdns":
						name = tag.text
		Host.attrib['name'] = name
	
	return findings
if __name__ == '__main__':
	for nessusScan in handleArgs():
		try:
			scanfile = ET.parse(nessusScan)
		except IOError:
			print("Can't find file: " + nessusScan)
			exit()
		xmlRoot = scanfile.getroot()
		for report in xmlRoot.findall('./Report'):
			findings = handleReport(report)
			# print(findings)
	scanfile.write(nessusScan.replace(".nessus", "") + '_Update.nessus')
	line_prepender(nessusScan.replace(".nessus", "") + '_Update.nessus', "<?xml version=\"1.0\" ?>")

