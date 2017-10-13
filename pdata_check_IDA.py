from idautils import *
from idc import *
from idaapi import *

Base=get_imagebase()
validInstructions = [ "ret", "retn", "jmp", "int3", "align", "db" ]

for ea in Segments():
    if SegName(ea) == ".pdata":
      size=SegEnd(ea)-SegStart(ea)
      pdataDump=get_many_bytes(SegStart(ea), size)
      for i in xrange(0, len(pdataDump), 12):
        subresult={}

        start=pdataDump[i:i+4][::-1].encode('hex')
        stop=pdataDump[i+4:i+8][::-1].encode('hex')

        subresult["StartVA"]="0x"+start
        subresult["StopVA"]="0x"+stop

        startAddr=int(start, 16)
        stopAddr=int(stop, 16)

        if startAddr == 0:
          break

        functionName = GetFunctionName(startAddr+Base)
        subresult["functionName"]=functionName

        ASM = []
        for head in Heads(startAddr+Base, stopAddr+Base):
          size=ItemSize(head)
          if head+size <= stopAddr+Base:
            #data="0x%08x"%head+": "+str(GetManyBytes(head, ItemSize(head)))+" "+GetDisasm(head)
            data=GetDisasm(head)
            ASM.append(data)

        subresult["ASM"]=ASM

        if ASM[-1].split()[0] in validInstructions:
          subresult["end"]="OK"
        else:
          subresult["end"]="KO"
          SetColor(startAddr+Base, CIC_FUNC, 0x2020c0)
       
        if  subresult["end"]=="KO":
          print subresult

