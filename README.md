# pdata_check

This python script is designed to identify unusual runtimes based on the pdata section and the last instruction of the runtime function.

You can find more information and an use case on the Talos blog post: http://blog.talosintelligence.com/2017/10/disassembler-and-runtime-analysis.html

The repository contains 2 scripts:

* pdata_check.py: a standalone script that displays unusual runtime functions based on the technique described on the blog post above

* pdata_check_IDA.py: an IDA Pro extension that performs the same tasks. This extension prints in the python windows the json output and colorize the functions in red in IDA Pro

Tested on the sample: 128aca58be325174f0220bd7ca6030e4e206b4378796e82da460055733bb6f4f (CCleaner compromise 2nd stage x64)

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
