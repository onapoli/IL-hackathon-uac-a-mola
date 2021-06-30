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
        self.q = None
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
                                    '''try:
                                        proc.memory_maps()
                                        continue
                                    except psutil.AccessDenied:
                                        pass
                                    except psutil.NoSuchProcess:
                                        continue'''
                                    proc.suspend()
                                    self.q.put({'name': proc.name(), 'pid': proc.pid})
                                    self._verifier(proc)

            time.sleep(1.0)

    def _verifier(self, sus_proc):
        while True:
            if not self.q.empty():
                response = self.q.get()
                if response == 'yes':
                    try:
                        sus_proc.resume()
                    except psutil.NoSuchProcess:
                        pass
                    print "\nSuspicious program execution resumed.\n"
                    continue
                sus_childs = sus_proc.children()
                sus_childs.append(sus_proc)
                for child in sus_childs:
                    try:
                        child.terminate()
                    except psutil.NoSuchProcess:
                        pass
                print "\nSuspicious program stopped.\n"
                break
            time.sleep(1.0)


    # This module must be always implemented, it is called by the run option
    def run_module(self):
        self.q = Queue()
        self.hunter = Process(target=self._hunter, args=())
        self.hunter.start()
        while True:
            if not self.q.empty():
                suspect = self.q.get()
                while True:
                    verification_prompt = "\nPossible malicious console launched by: {}\n\nDo you trust it?\nEnter Yes or No: ".format(suspect['name'])
                    response = raw_input(verification_prompt)
                    response = response.lower()
                    if response != 'yes' and response != 'no':
                        continue
                    break
                self.q.put(response)
            time.sleep(1.0)
    
    def stop_module(self):
        if self.hunter:
            self.hunter.terminate()
        if self.q:
            self.q.close()
        