from multiprocessing.connection import Listener
from multiprocessing import Process, RLock, Event
from winreg import *
import admin
import os
from _winreg import HKEY_CURRENT_USER as HKCU
from _winreg import HKEY_LOCAL_MACHINE as HKLM
from support.brush import Brush
import ctypes
import sys
import time


class CustomListener:

    DEBUG_KEY = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\"

    # Created two new class properties, binlist and listener, to access their
    # values when stop_module is called. 
    def __init__(self, password, port):
        self.password = password
        self.port = port
        self.agents_path = self.agents_path()
        self.brush = Brush()
        self.binlist = None
        self.listener = None

    def agents_path(self):
        dirpath = os.path.dirname(os.path.realpath(__file__))
        return str(dirpath) + "\\agents\\"

    # create_listener will create the listener process and wait indefinately
    # until the user sends an interruption signal that will generate the call
    # to stop_module.
    def listen(self, binlist):
        """
        Listen for the execution of a list of
        binaries
        """
        if binlist is None or binlist == []:
            print "Empty list of binaries"
            return
        # This module must be executed as administrator
        if not admin.isUserAdmin():
            print "ERROR: Please run uacamola as ADMINISTRATOR"
            return
        registry = Registry()
        self.binlist = binlist
        self._add_debugger(registry)
        self._create_listener()
        return
    
    # If there is a listener process running, terminates the process
    # and deletes the registry values that were added with _add_debugger.
    def stop_listener(self):
        if self.listener is None:
            return
        self.listener.terminate()
        registry = Registry()
        self._del_debugger(registry)

    # Creates the listener process, starts it, and waits for it using
    # an Event object, which is non-blocking, allowing the program to
    # receive the interruption signal that terminates the process.
    # Waiting for the process with join, blocked program execution
    # completely and signals where not received during that state.
    def _create_listener(self):
        #while True:
        event = Event()
        self.listener = Process(target=self._listen, args=(event,))
        self.listener.start()
        print "\nPress Ctrl + c to quit mitigation mode.\n"
        event.wait()

    # This is the listener process, it includes an infinite loop where
    # client connections are started and closed each time a message is received.
    def _listen(self, event):
        """ Listen for information from a client and performs
        actions related to the windows registry """
        registry = Registry()
        listener = Listener(('localhost', self.port), authkey=self.password)
        while True:
            conn = listener.accept()
            msg = conn.recv()
            if type(msg) is list and len(msg) == 2:
                # Deleting debugger key
                debug_path = self.DEBUG_KEY + msg[0]
                k = registry.open_key(HKLM, debug_path)
                registry.del_value(k, "debugger")
                # Deleting the bad path
                k = registry.open_key(HKCU, msg[1])
                if k:
                    self.brush.color("[!!] POSSIBLE UAC BYPASS IN YOUR SYSTEM\n", 'RED')
                    registry.delete_key(HKCU, msg[1])
                    ctypes.windll.user32.MessageBoxA(
                        None, "UAC BYPASS DETECTADO Y MITIGADO. EJECUCION SEGURA DEL BINARIO", "PELIGRO!", 0)
                os.system(msg[0])
                # Setting the debugger key before breaking connection
                k = registry.open_key(HKLM, debug_path)
                payload = self.build_payload(msg[0][:-3] + "pyw")            
                registry.create_value(k,
                                    "debugger",
                                    payload)
                print "Mitigated malicious execution of {}".format(msg[0])
                conn.close()

    def _add_debugger(self, registry):
        """ Adds debugger registry key for 
        each of the processes in the list """
        for binary in self.binlist:
            path = self.DEBUG_KEY + binary
            k = registry.open_key(HKLM, path)
            if not(k):
                k = registry.create_key(HKLM, path)
            payload = self.build_payload(binary[:-3] + "pyw")
            registry.create_value(k,
                                  "debugger",
                                  payload)
    
    # Now the binlist is obtained from the correspondent class property,
    # not as an argument. 
    def _del_debugger(self, registry):
        """ Deletes debugger registry key for 
        each of the processes in the list """
        for binary in self.binlist:
            path = self.DEBUG_KEY + binary
            k = registry.open_key(HKLM, path)
            if not(k):
                return
            registry.del_value(k, "debugger")            

    def build_payload(self, binary):
        return "mshta vbscript:Execute(\"CreateObject(\"\"Wscript.Shell\"\").Run \"\"powershell -Command \"\"\"\"& '%s%s'\"\"\"\"\"\", 0 : window.close\")" % (self.agents_path, binary)
