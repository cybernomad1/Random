import os, streams, parsexml, strutils

if paramCount() < 1:
  quit("./parseNessus NessusFIle")

var filename = paramStr(1)
var s = newFileStream(filename, fmRead)

if s == nil: quit("cannot open the file " & filename)

var
    ip = ""
    port = ""
    svc_name = ""
    protocol = ""
    plugin = ""
    line: seq[string] = @[]

var x: XmlParser
open(x, s, filename)
next(x)

block mainLoop:
  while true:
    case x.kind
    of xmlElementOpen:
        if x.elementName == "ReportHost":
            x.next()
            if x.attrKey == "name":
                ip = x.attrValue
        elif x.elementName == "ReportItem":
            x.next()
            
            if x.attrkey == "port" and x.attrValue != "0":
                port = x.attrValue
                x.next()
                svc_name = x.attrValue
                x.next()
                protocol = x.attrValue
                x.next()
                x.next()
                x.next()
                plugin = x.attrValue
                
                if plugin == "Nessus SYN scanner":
                    line.add(ip & "," & svc_name & "," & port & "," & protocol)
        else:
            x.next()
    of xmlEof: break # end of file reached
    of xmlError:
        echo(errorMsg(x))
        x.next()
    else:
        x.next()
x.close()

let f = open("NessusSynScan_Results.csv", fmWrite)

for element in line:
    f.writeLine(element)
    echo element

echo "Results exported to NessusSynScan_Results.csv"
f.close

