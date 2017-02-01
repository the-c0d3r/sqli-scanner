import argparse
import logging
import multiprocessing
import urllib

from lib.conf     import settings
from lib.cleaner  import deduplicate
from lib.reader   import FileReader
from lib.writer   import FileWriter
from lib.colour   import colours
from lib.reporter import Report

global lock
lock = multiprocessing.Lock()


class URLHandler:
    def __init__(self, url):
        """
        Handles the url into formatted url
        :param url: URL to handle
        """
        self.url = url
        if self.url is None:
            pass
        elif self.url is not None:
            if "http://" not in self.url:
                self.url = "http://" + self.url
            if "'" not in self.url:
                self.url = self.url + "'"
            if "=" not in self.url:
                 self.url = None
                 # TODO Handle NONE type in tester


    def getContent(self):
        """
        returns the content of the url
        """
        try:
            if self.url == None:
                return ""
            else:
                return urllib.urlopen(self.url).read()
        except IOError:
            print("[-] Network Error Occured")

    def vulnerable(self):
        """
        Checks if it is vulnerable
        Return : boolean
        """
        self.content = self.getContent()
        if self.content != None:
            for error in settings().sql_errors:
                if error in self.content:
                    return True
            return False

class worker(multiprocessing.Process):
    """ Inherit from Multiprocessing.Process class """
    def __init__(self, procName, taskQ, resultQ):
        """
        Initiate the worker object
        :param procName: the name of the worker process
        :param taskQ: the Queue object to get the jobs from
        :param resultQ: the Queue object to store results
        """
        multiprocessing.Process.__init__(self)
        self.name = procName
        self.taskQ = taskQ
        self.resultQ = resultQ

    def run(self):
        while True:
            next_task = self.taskQ.get()
            if next_task is None:
                # None means stop
                logging.debug("[-] Stopping %s Process", self.name)
                self.taskQ.task_done()
                break
            logging.debug("[+] Worker : %s working on %s", self.name, next_task)
            vuln = next_task.vulnerable()
            result = next_task.url
            if vuln:
                with lock:
                    Report(result, vuln)
                self.resultQ.put(result)
            else:
                with lock:
                    Report(result, vuln)

class controller:
    def __init__(self, inFile, outFile):
        """
        Initiate controller procedure
        :param inFile: the file containing the URLs
        :param outFile: the output file, "result.txt" by default
        """
        try:
            self.urllist = deduplicate(FileReader(inFile).read()).result

            self.start()
            logging.info("[+] All work done, saving file")
        except KeyboardInterrupt:
            print("Stopping processes")
            for proc in self.workers:
                proc.terminate()
        finally:
            result = []
            while not self.resultQ.empty():
                temp = self.resultQ.get()
                if temp != None:
                    result.append(str(temp))
            FileWriter(outFile, result)

    def start(self):
        self.taskQ = multiprocessing.JoinableQueue()
        self.resultQ = multiprocessing.Queue()
        self.workerCount = multiprocessing.cpu_count() * 2
        self.workers = []

        for url in self.urllist:
            # populates the Task Queue
            self.taskQ.put(URLHandler(url))

        for i in range(self.workerCount):
            # populates the workers list and create workers
            tempWorker = worker(str(i), self.taskQ, self.resultQ)
            self.workers.append(tempWorker)

        for x in range(self.workerCount):
            # add ending tasks to the processes
            # Signals the processes that the job is done
            self.taskQ.put(None)

        logging.info("[+] Generating %d worker processes", self.workerCount)


        for w in self.workers:
            # Makes the worker start doing jobs
            w.start()

        # Waits for the tasks to finish
        for w in self.workers:
            w.join()


def handle_args():
    """
    A function to parse the command argument
    And control the main program
    """
    parser = argparse.ArgumentParser(prog="Union Based SQL Injector",description="Union Based SQL injector")
    parser.add_argument("-f", "--file", help="Target file with URLs")
    parser.add_argument("-o", "--output", help="Output file to save vulnerable websites to")
    parser.add_argument("-v", "--verbose",help="Enable Verbose mode",action="store_true")
    args = parser.parse_args()

    if args.file == None:
        parser.print_help()
        exit()

    elif args.file != None:
        if args.verbose:
            logging.basicConfig(format="%(levelname)s: %(message)s", level=logging.DEBUG)
            logging.info("Verbose mode Activated")
        else:
            logging.basicConfig(format="%(levelname)s: %(message)s")
        if args.output == None:
            args.output = "result.txt"

        # try:
        controller(args.file, args.output)
        # except KeyboardInterrupt:
            # print("\n[~] Exiting...")
        # except Exception as e:
        #     logging.warning(e)
        #     print("\n[!] Error Occured")
        #     print(e)
        #     exit()

if __name__ == "__main__":
    handle_args()
