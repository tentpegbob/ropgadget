# ROPgadget

This is a Python script that can be used with GDB. It imports modules from Jonathan Salwan's ROPgadget tool located at https://github.com/JonathanSalwan/ROPgadget. As such, it's actually a dependency that must be install via pip install ropgadget or pip3 install ropgadget. Otherwise this script won't be very valuable at all.

## How to use it:
```pip install ropgadget``` or  
```pip3 install ropgadget```  

run gdb then type ```source ROPgadget.py```

In order for ```ROPgadget``` to work a file must be loaded into gdb's current running state. For example you can type: ```file /bin/ls``` and then type ```ROPgadget``` to find all the gadgets inside the ls binary. ```help ROPgadget``` will give you any available options
