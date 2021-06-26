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
        # Creating a thread that will create the listeners
        #create_listeners = Process(target=self._create_listeners, args=())
        #create_listeners.start()
        self._create_listener()
        # Waiting for exiting
        #raw_input("\n--- Press ENTER for quit mitigate mode ---\n\n")
        #self.del_debugger(registry, binlist)
        return
    
    def stop_listener(self):
        if self.listener is None:
            return
        self.listener.terminate()
        registry = Registry()
        self._del_debugger(registry)

    def _create_listener(self):
        #while True:
        event = Event()
        self.listener = Process(target=self._listen, args=(event,))
        self.listener.start()
        print "\nPress Ctrl + c to quit mitigation mode.\n"
        event.wait()
        #self.listener.join()
            
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
