#! /usr/bin/python3

import xml.etree.ElementTree as etree
import os
import csv
import argparse
from collections import Counter
from time import sleep


def get_host_data(root):
    host_data = []
    hosts = root.findall('host')
    for host in hosts:
        #addr_info = []

        # Ignore hosts that are not 'up'
        if not host.findall('status')[0].attrib['state'] == 'up':
            continue
        
        # Get IP address and host info. If no hostname, then ''
        ip_address = host.findall('address')[0].attrib['addr']
        
        # Get information on ports and services
        try:
            port_element = host.findall('ports')
            ports = port_element[0].findall('port')
            for port in ports:
                port_data = []

                # Ignore ports that are not 'open'
                if not port.findall('state')[0].attrib['state'] == 'open':
                    continue
                
                proto = port.attrib['protocol']
                port_id = port.attrib['portid']
                service = port.findall('service')[0].attrib['name']

                # Create a list of the port data
                port_data.extend((ip_address, service, port_id, proto))
                
                # Add the port data to the host data
                host_data.append(port_data)
        except:
            print("error parsing xml file")
    return host_data


def parse_xml(filename):
    try:
        tree = etree.parse(filename)
    except Exception as error:
        print("[-] A an error occurred. The XML may not be well formed. "
              "Please review the error and try again: {}".format(error))
        exit()
    root = tree.getroot()
    scan_data = get_host_data(root)
    return scan_data

def parse_to_csv(data):
    if not os.path.isfile(csv_name):
        csv_file = open(csv_name, 'w', newline='')
        csv_writer = csv.writer(csv_file)
        top_row = ['IP Address', 'Name', 'Port', 'Protocol', 'Details']
        csv_writer.writerow(top_row)
        print('\n[+] The file {} does not exist. New file created!\n'.format(csv_name))
    else:
        try:
            csv_file = open(csv_name, 'a', newline='')
        except:
            print("\n[-] Permission denied to open the file {}. "
                  "Check if the file is open and try again.\n".format(csv_name))
            print("Print data to the terminal:\n")
            for item in data:
                print(' '.join(item))
            exit()
        csv_writer = csv.writer(csv_file)
        print('\n[+] {} exists. Appending to file!\n'.format(csv_name))
    for item in data:
        csv_writer.writerow(item)
    csv_file.close()        



def main():
    for filename in args.filename:
        if not os.path.exists(filename):
            parser.print_help()
            print("\n[-] The file {} cannot be found or you do not have "
                  "permission to open the file.".format(filename))
            continue
        with open(filename) as fh:
            contents = fh.read()
            if '<!entity' in contents.lower():
                print("[-] Error! Invalid Nmap XML File. Ignoring {}".format(filename))
                continue
        data = parse_xml(filename)
        parse_to_csv(data)



if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument("-csv", "--csv",
                        nargs='?', const='scan.csv',
                        help="Specify the name of a csv file to write to. "
                             "If the file already exists it will be appended")
    parser.add_argument("-f", "--filename",
                        nargs='*',
                        help="Specify a file containing the output of an nmap "
                             "scan in xml format.")

    args = parser.parse_args()

    if not args.filename:
        parser.print_help()
        print("\n[-] Please specify an input file to parse. "
              "Use -f <nmap_scan.xml> to specify the file\n")
        exit()
    if not args.csv:
        parser.print_help()
        print("\n[-] Please specify an output file to create. Use -csv <nmap_scan.csv> to specify the file\n")

    csv_name = args.csv
    main()
    print("\n[+] Finished parsing Nmap results. View {} for results!\n".format(csv_name))

                