from common import utils
import re
import collections
import json
import sys
from datetime import datetime


class AddrsetParser:
    """
    This class is usead to read and parse the output of the command
    vsipioctl getaddrsets -f <filter_name>
    """

    # Class Variables
    REGEX_ADDRSET_STRING = r"""(?: #Non Capturing Parenthesis
        # Match the actual vsipioctl command if its been included in the file
        (?:.*vsipioctl\s+getaddrsets\s+-f\s+(?P<filter_name>\S+)$)
        | # Match the beginning of an addrset
        (?:^addrset\s+(?P<name>\S+)\s+[{}]$)
        | # Match an addrset entry
        (?:^ip\s+(?P<address>\S+),$)
        | # Match closing bracket
        (?:^[}]$)
    ) #Close Non Capturing Parenthesis
    """
    REGEX_ADDRSET_MATCH = re.compile(REGEX_ADDRSET_STRING, re.VERBOSE)
    REGEX_IGNORE = re.compile(
        "\ .#\ (generation|realization|ruleset|Filter\ rules)")

    def __init__(self, file_name):
        self.addrsets = collections.OrderedDict()
        utils.validate_file(file_name)
        self.file_name = file_name
        self.t = open(file_name, 'r')
        self.load_addrsets(self.t)
        self.close()

    def close(self):
        if self.t:
            self.t.close()
            self.t = None

    def add_new_addrset(self, name):
        if name not in self.addrsets:
            self.addrsets[name] = []

    def add_new_addrset_entry(self, name, entry):
        if name not in self.addrsets:
            raise "%s not found in dict"
        self.addrsets[name].append(entry)

    def dump_addrsets(self):
        print(json.dumps(self.addrsets, ensure_ascii=False, indent=4))

    def get_addrsets(self):
        return self.addrsets

    def load_addrsets(self, fileObject):
        print('  --> Parsing address sets')

        # Variable to keep a track of the current addrset name
        addrset_name = None
        containerCounter = 0
        entryCounter = 0
        startTime = datetime.now()

        for i, line in enumerate(fileObject):
            line = line.rstrip()
            ignorematch = re.search(self.REGEX_IGNORE, line)
            globalmatch = re.search(self.REGEX_ADDRSET_MATCH, line)
            if globalmatch:
                if globalmatch.group('name'):
                    addrset_name = globalmatch.group('name')
                    self.add_new_addrset(addrset_name)
                    containerCounter += 1
                if globalmatch.group('address'):
                    self.add_new_addrset_entry(
                        addrset_name, globalmatch.group('address'))
                    entryCounter += 1

                print(' ' * 80, end='\r')
                print('  --> Processing %s entries in %s total address sets.' %
                      (entryCounter, containerCounter), end='\r')
                sys.stdout.flush()

        finishTime = datetime.now() - startTime
        print('  --> Processed %s entries from %s total address sets in %s' %
              (entryCounter, containerCounter, finishTime))
