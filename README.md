# Random
Random scripts that fit particular usecases/make life easier. Scripts work for me, everything else is user error :)

|File   	|Description   	|
|---	|---	|
|NessusNameUpdater.py| Update hostname with FQDN if it was found|
|Nmap2CSV.py|Generate csv table from NMAP XML|
|PTRNessusParser.py|Add unique ref to nessus, generate PSN ITHC csv, Generate stats xlsx|
|SAMCheck.py| Cross reference account names against ntds.dit cracked passwords|
|CE_CVSS_Converter.py| Calculate CE+ aligned CVSSv3 score and amend nessus file, also prints out Fail and Action points|
|NessusParser.nim| Nim script to parse nessus file for open ports and create CSV|
|log4shell.py|Python script to check for log4shell vuln|


---
## NessusNameUpdater.py

```
usage:
python3 NessusNameUpdater.py input.nessus

Nessus Interpreter.

positional arguments:
  nessus_xml_files  nessus xml file to parse

optional arguments:
  -h, --help        show this help message and exit
  ```
 ---
## Nmap2CSV.py
```
usage: python3 Nmap2CSV.py [-h] [-csv [CSV]] [-f [FILENAME [FILENAME ...]]]

optional arguments:
  -h, --help            show this help message and exit
  -csv [CSV], --csv [CSV]
                        Specify the name of a csv file to write to. If the
                        file already exists it will be appended
  -f [FILENAME [FILENAME ...]], --filename [FILENAME [FILENAME ...]]
                        Specify a file containing the output of an nmap scan
                        in xml format.
 ```
 ---
 ## PTRNessusParser.py

```
usage:
python3 PTRNessusParser.py -d NessusFileDirectory -p ProjectID


optional arguments:
  -h, --help            show this help message and exit
  -d DIRECTORY [DIRECTORY ...], --directory DIRECTORY [DIRECTORY ...]
                        directory containing .nessus files to parse
  -p PROJECTID [PROJECTID ...], --projectID PROJECTID [PROJECTID ...]
                        Project ID
                        
  OUTPUT:
  [ProjectID]_Stats.xlsx -> Excel file containing metrics for graphs
  [ProjectID]_nessusScan.nessus -> Merged nessus file with unique issue reference values
  [ProjectID]_PSNITHC.csv -> PSNITHC compliant csv ready for making bespoke for client
  ```
  ---
  ## SAMCheck.py
  
  ```
  usage:
python3 SAMCHECK.py -s SAMFile -h Hashes input.nessus

SAM CHECK

optional arguments:
  -h, --help            show this help message and exit
  -s SAMFILE [SAMFILE ...], --samfile SAMFILE [SAMFILE ...]
                        File contaning active users
  -c CRACKEDHASHES [CRACKEDHASHES ...], --crackedhashes CRACKEDHASHES [CRACKEDHASHES ...]
                        File containing cracked hashes
  ```
  ---
  
  ## CE_CVSS_Converter.py
  ```
  usage:
python3 CE_CVSS_Converter.py input.nessus

CEPLUS Nessus Interpreter.


positional arguments:
  nessus_xml_files  nessus xml file to parse

optional arguments:
  -h, --help        show this help message and exit
  ```

## NessusParser.nim

```
compile:
nim c NessusParser.nim

usage:
./NessusParser NessusReportFile

outputs NessusSynScan_Results.csv in same directory


## log4shell.py

```
compile:
usage:
python3 log4shell.py -u url -c burpCollaborator
python3 log4shell.py -U urlList -c burpCollaborator
