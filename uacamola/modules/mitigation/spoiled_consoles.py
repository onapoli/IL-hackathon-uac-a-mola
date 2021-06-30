#--encoding: utf-8--

from module import Module
from multiprocessing import Process, Queue, Pipe, Event
import psutil
import time


class CustomModule(Module):
    def __init__(self):
        information = {"Name": "Spoiled Consoles",
                       "Description": "Detects when elevated consoles are launched and checks if consent.exe was executed previously.",
                       "Author": "Omar Napoli"}

        # -----------name-----default_value--description--required?
        options = {}

        # Constructor of the parent class
        super(CustomModule, self).__init__(information, options)

        # Class atributes, initialization in the run_module method
        # after the user has set the values
        self.hunter = None
        self.verifier = None
        self.suspects = None
        self.verification_parent = None
        self.consoles = {'cmd.exe', 'powershell.exe'}
    
    def _hunter(self):
        while True:
            conns = psutil.net_connections(kind='tcp')
            for conn in conns:
                proc = psutil.Process(conn.pid)
                # External program
                exe_path = proc.exe()
                if not exe_path.startswith("C:\\Windows"):
                    if proc.children():
                        for child in proc.children():
                            # Launched a console
                            if child.name() in self.consoles:
                                #
                                # Another program that is not running anymore
                                # executed this program.
                                # If the user had manually executed the program, explorer.exe
                                # would appear as its parent process.
                                #
                                if not proc.parents():
                                    #
                                    # Failing to access some part of the program's memory might
                                    # relate this program with protected system resources that
                                    # were used by its mysterious parent.
                                    # I am not sure about this.
                                    #
                                    try:
                                        print proc.memory_maps()
                                        continue
                                    except psutil.AccessDenied:
                                        pass
                                    except psutil.NoSuchProcess:
                                        continue
                                    proc.suspend()
                                    self.suspects.put({'name': proc.name(), 'pid': proc.pid()})
            time.sleep(1.0)

    def _verifier(self, verification):
        while True:
            if not self.suspects.empty():
                suspect = self.suspects.get()
                verification.send(suspect)
                response = verification.recv()
                sus_proc = psutil.Process(suspect['pid'])
                if response == 'yes':
                    try:
                        sus_proc.resume()
                    except psutil.NoSuchProcess:
                        pass
                    continue
                sus_childs = sus_proc.children()
                sus_childs.append(sus_proc)
                for child in sus_childs:
                    try:
                        child.terminate()
                    except psutil.NoSuchProcess:
                        pass
            time.sleep(1.0)


    # This module must be always implemented, it is called by the run option
    def run_module(self):
        self.suspects = Queue()
        self.hunter = Process(target=self._hunter, args=())
        self.hunter.start()
        self.verification_parent, verification_child = Pipe()
        self.verifier = Process(target=self._verifier, args=(verification_child,))
        self.verifier.start()
        while True:
            suspect = self.verification_parent.recv()
            while True:
                verification_prompt = "Possible malicious spoiled console launched by: {}\n\nDo you trust it?\nEnter Yes or No: ".format(suspect['name'])
                response = raw_input(verification_prompt)
                response = response.lower()
                if response != 'yes' and response != 'no':
                    continue
                break
            self.verification_parent.send(response)
    
    def stop_module(self):
        if self.hunter:
            self.hunter.terminate()
        if self.verifier:
            self.verifier.terminate()
        if self.verification_parent:
            self.verification_parent.close()
        if self.suspects:
            self.suspects.close()
        