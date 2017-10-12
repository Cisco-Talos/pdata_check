#!/usr/bin/python

import pefile
import sys
import os
import struct
import pprint
from capstone import *

class pdata_scan:
  def __init__(self, data):
    self.data=data
    self.pe=None
    self.isPE=False
    self.isX64=False
    self.hasPDATA=False
    self.hasTEXT=False
    self.pdataOffset=0
    self.pdataSize=0
    self.VA=0
    self.PointerToRawData=0
    self.result={}

    self.validInstructions = [ "ret", "retn", "jmp", "int3" ]

    try:
      self.pe=pefile.PE("",data)
      self.isPE=True
    except:
      pass

    if pefile.MACHINE_TYPE[self.pe.FILE_HEADER.Machine] == "IMAGE_FILE_MACHINE_AMD64":
      self.isX64=True
    
    if self.checkPDATA() == True:
      self.hasPDATA=True
      #Dump .pdata section
      if self.checkTEXT() == True:
        self.hasTEXT=True
        pdataDump=self.data[self.pdataOffset:self.pdataOffset+self.pdataSize]
        try:
          self.parsePDATA(pdataDump)
        except:
          print "Cannot parse the .pdata section..."
    else:
      pass

  def parsePDATA(self, pdataDump):
    index=0
    for i in xrange(0, len(pdataDump), 12):
      subresult={}
      start=pdataDump[i:i+4][::-1].encode('hex')
      subresult["StartVA"]="0x"+start

      stop=pdataDump[i+4:i+8][::-1].encode('hex')
      subresult["StopVA"]="0x"+stop

      rawStart = int(start, 16) - self.VA + self.PointerToRawData
      subresult["StartRaw"]=hex(rawStart)

      rawStop = int(stop, 16) - self.VA + self.PointerToRawData
      subresult["StopRaw"]=hex(rawStop)

      code=self.data[rawStart:rawStop]
      md=Cs(CS_ARCH_X86, CS_MODE_64)
      ASM=[]
      for i in md.disasm(code, 0x1000):
        ASM.append(i.mnemonic+" "+i.op_str)
      subresult["ASM"]=ASM
      if ASM[-1].split()[0] in self.validInstructions:
        subresult["end"]="OK"
      else:
        subresult["end"]="KO"
        subresult["lastASM"]=ASM[-1]
      self.result[index]=subresult
      index=index+1

  def checkTEXT(self):
    if self.isPE == False:
      return False
    elif self.isX64 == False:
      return False
    else:
      for sec in self.pe.sections:
        if sec.Name.replace('\x00','') == ".text":
          self.VA=sec.VirtualAddress
          self.PointerToRawData=sec.PointerToRawData
          return True

  def checkPDATA(self):
    if self.isPE == False:
      return False
    elif self.isX64 == False:
      return False
    else:
      for sec in self.pe.sections:
        if sec.Name.replace('\x00','') == ".pdata":
          self.pdataOffset=sec.PointerToRawData
          self.pdataSize=sec.Misc_VirtualSize
          return True
    return False

if __name__ == '__main__':
  try:
    filename=sys.argv[1]
    file=open(filename, "rb")
    data=file.read()
    file.close()

    p=pdata_scan(data)

    if p.isPE == True:
      if p.isX64 == True:
        if p.hasPDATA == True:
          if p.hasTEXT == True:
            for i in p.result:
               if p.result[i]["end"] == "KO":
                 pp = pprint.PrettyPrinter(indent=2)
                 pp.pprint(p.result[i])
          else:
            print "No .text section"
        else:
          print "No .pdata section"
      else:
        print "The PE is not a 64b PE"
    else:
      print "The filename is not a valid PE"

  except:
    print "%s filename" % sys.argv[0]
exit()
