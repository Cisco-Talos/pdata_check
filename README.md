#pdata_check

This python script is designed to identify unusual runtimes based on the pdata section and the last instruction of the runtime function.

You can find more information and an use case on the Talos blog post: http://blog.talosintelligence.com/2017/10/disassembler-and-runtime-analysis.html

# Prerequisites

* captsone: https://github.com/aquynh/capstone

# Examples of usage

```
user@lab:$ ./pdata_check.py sample.exe
{ 'ASM': [ u'mov qword ptr [rsp + 0x18], rbx',
u'push rdi',
u'sub rsp, 0x20',
[...redacted]
u'mov qword ptr [rip + 0x3ac8], r11',
u'mov rbx, qword ptr [rsp + 0x40]',
u'add rsp, 0x20',
u'pop rdi'],
'StartRaw': '0xea20',
'StartVA': '0x0000f620',
'StopRaw': '0xead3',
'StopVA': '0x0000f6d3',
'end': 'KO',
'lastASM': u'pop rdi'}
```
