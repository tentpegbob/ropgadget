''''Borrowed from https://github.com/JonathanSalwan/ROPgadget and follows
the BSD 3-Clause "New" or "Revised" License.
'''
import re
import ropgadget

class GadgetFinder(gdb.Command):
    """ROPgadget extends GDB by calling specific methods from the ROPgadget tool
Available options which can be set to True or False:
    rawArch, rawMode, norop, nosys, nojop, multibr, dump
Available options which can have unsigned integer values:
    offset
    """
    binary = "file"
    gadgets = []
    rawArch = False
    rawMode = False
    thumb = False
    norop = True
    nojop = True
    nosys = True
    offset = 0
    depth = 5
    multibr = True
    dump = False

    def __init__(self):
        super (GadgetFinder, self).__init__("ROPgadget", gdb.COMMAND_SUPPORT, gdb.COMPLETE_NONE, True)

    def invoke(self, arg, from_tty):
        self.__reset_values()
        if arg:
            for x in gdb.string_to_argv(arg):
                if x == "rawArch=True":
                    self.rawArch = True
                if x == "rawMode=True":
                    self.rawMode = True
                if x == "norop=True":
                    self.norop = False
                if x == "nojop=True":
                    self.nojop = False
                if x == "nosys=True":
                    self.nosys = False
                try:
                    val = int(x[6:], 10)
                    if val > 0:
                        self.offset = val
                except:
                    self.offset = 0
                if x == "dump=True":
                    self.dump = True

        binaryFileName = gdb.execute("info target", to_string=True)
        if binaryFileName == "":
            print("No files are currently loaded")
            return False
        else:
            self.binary = re.findall("`(...*)',", binaryFileName)[0]

        bin = ropgadget.binary.Binary(self)
        self.binary = bin
        gad = ropgadget.gadgets.Gadgets(binary=bin, options=self, offset=self.offset)
        self.gadgets = gad

        execSections = bin.getExecSections()

        gadgets = []
        for section in execSections:
            if self.norop:
                gadgets += gad.addROPGadgets(section)
            if self.nojop:
                gadgets += gad.addJOPGadgets(section)
            if self.nosys:
                gadgets += gad.addSYSGadgets(section)

        gadgets = gad.passClean(gadgets, self.multibr)
        gadgets = ropgadget.rgutils.deleteDuplicateGadgets(gadgets)
        gadgets = ropgadget.rgutils.alphaSortgadgets(gadgets)

        self.gadgets = gadgets
        self.print_gadgets()

    def print_gadgets(self):
        if self.gadgets == []:
            return False

        try:
            arch = self.binary.getArchMode()
        except:
            return False

        print("Gadgets information\n" + "=" *70)
        for gadget in self.gadgets:
            vaddr = gadget["vaddr"]
            insts = gadget["gadget"]
            bytes = gadget["bytes"]
            bytesStr = " // " + bytes.hex() if self.dump else ""

            print(("0x%08x" %(vaddr) if arch == "32" else "0x%016x" %(vaddr)) + " : %s" %(insts) + bytesStr)

        print("\nUnique gadgets found: %d" %(len(self.gadgets)))
        return True

    def __reset_values(self):
        self.dump = False
        self.offset = 0
        self.nosys = True
        self.nojop = True
        self.norop = True
        self.rawMode = False
        self.rawArch = False

GadgetFinder()
