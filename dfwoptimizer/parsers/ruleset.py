from common import utils
import re
import collections
import sys
import json
import csv
import math
import ipaddress
from datetime import datetime


class RulesParser:
    """
    This class is usead to read and parse the output of the command
    vsipioctl getrules -f <filter_name>
    """

    # Class Variables
    REGEX_RULE_STRING = r"""(?: #Non Capturing Parenthesis
        # match the closing curly brace
        (^(?P<closingBracket>\}))
        # ruleset domain-c132380_L2 {
        | (?:^ruleset\s+(?P<L2_ruleset_name>\S+L2)\s+[{])
        # ruleset domain-c132380 {
        | (^ruleset\s+(?P<L3_ruleset_name>\S+)\s+[{])
        # ##########################################################################
        # region L2 Ethernet Rules
        #   rule 2858 at 1 inout ethertype any stateless from any to any accept;
        | (?:
        ^(\s+)?rule
        \s+(?P<L2T1_ruleid>\d*)
        \sat
        \s(?P<L2T1_rulePosition>\d*)
        \s(?P<L2T1_ruleDirection>\S+)
        \s(?P<L2T1_ruleProtocol>ethertype)
        \s(?P<L2T1_ruleSubProtocol>\S+)
        (?:\s+stateless)?
        \sfrom
        \s(?:
        (?P<L2T1_ruleSourceAny>any) # from any
        # from mac-securitygroup-13
        | (?:addrset\s+(?P<L2T1_ruleSourceAddrset1>\S+))
        # from not mac-securitygroup-13
        | (?P<L2T1_RuleSourceNegated>not)\s+addrset\s+(?P<L2T1_ruleSourceAddrset2>\S+)
        )
        \sto
        \s(?:
        (?P<L2T1_ruleDestinationAny>any) # to any
        # to mac-securitygroup-13
        | (?:addrset\s+(?P<L2T1_ruleDestinationAddrset1>\S+))
        # to not mac-securitygroup-13
        | (?P<L2T1_RuleDestinationNegated>not)\s+addrset\s+(?P<L2T1_ruleDestinationAddrset2>\S+)
        )
        \s(?P<L2T1_ruleAction>\S+) # accept|drop
        (?:\s+with\s+(?P<L2T1_ruleLogging>log))? # with log
        (?:\s+tag\s+\'(?P<L2T1_ruleTag>.*)\')? # tag 'insert_witty_tag_here'
        \;$)
        # endregion
        # ##########################################################################
        # region L3 Rules Type 0 (Any)
        | (?:
        ^(\s+)?rule
        \s+(?P<L3T0_ruleid>\d*)
        \sat
        \s(?P<L3T0_rulePosition>\d*)
        \s(?P<L3T0_ruleDirection>\S+)
        (?:\s(?P<L3T0_ruleAddressFamily>\S+))?
        \sprotocol
        \s(?:
        # Standard Non-Port protocols
        (?P<L3T0_ruleProtocol>any|igmp|gre|ipv6-crypt|sctp|ip|pim|240|vrrp|ipv6-opts|ipv6-nonxt)
        )
        (?:\s+stateless)?
        (?:\s+strict)?
        \sfrom
        \s(?:
        (?P<L3T0_ruleSourceAny>any) # from any
        # from ip-securitygroup-13
        | (?:addrset\s+(?P<L3T0_ruleSourceAddrset1>\S+))
        # from not ip-securitygroup-13
        | (?P<L3T0_RuleSourceNegated>not)\s+addrset\s+(?P<L3T0_ruleSourceAddrset2>\S+)
        # from ip xx.xx.xx.xx
        | (?:ip\s+(?P<L3T0_ruleSourceAddrset3>\S+))
        # from not ip xx.xx.xx.xx
        | (?P<L3T0_RuleSourceNegated1>not)\s+ip\s+(?P<L3T0_ruleSourceAddrset4>\S+)
        )
        \sto
        \s(?:
        (?P<L3T0_ruleDestinationAny>any) # to any
        # to mac-securitygroup-13
        | (?:addrset\s+(?P<L3T0_ruleDestinationAddrset1>\S+))
        # to not mac-securitygroup-13
        | (?P<L3T0_RuleDestinationNegated>not)\s+addrset\s+(?P<L3T0_ruleDestinationAddrset2>\S+)
        # to ip xx.xx.xx.xx
        | (?:ip\s+(?P<L3T0_ruleDestinationAddrset3>\S+))
        # from not ip xx.xx.xx.xx
        | (?P<L3T0_RuleDestinationNegated1>not)\s+ip\s+(?P<L3T0_ruleDestinationAddrset4>\S+)
        )
        # with attribute addrset attr_1092_1_APP_ID
        (?:\s+with\s+attribute(?:\s+addrset)?\s+(?P<L3T0_ruleAttribute>\S+))?
        \s+
        (?P<L3T0_ruleAction>\S+) # accept|drop|punt
        (?:\s+with\s+(?P<L3T0_ruleLogging>log))? # with log
        (?:\s+tag\s+\'(?P<L3T0_ruleTag>.*)\')? # tag 'insert_witty_tag_here'
        \;$)
        # endregion
        # ##########################################################################
        # region L3 Rules
        | (?:
        ^(?:(\s+)?\#\s+(?P<L3T1_ruleInternal>internal)\s+\#)?
        (\s+)?rule
        \s+(?P<L3T1_ruleid>\d*)
        \sat
        \s(?P<L3T1_rulePosition>\d*)
        \s(?P<L3T1_ruleDirection>\S+)
        (?:\s(?P<L3T1_ruleAddressFamily>\S+))?
        \sprotocol
        \s(?:
        (?P<L3T1_ruleProtocol>tcp|udp) # Standard protocols
        )
        (?:\s+stateless)?
        (?:\s+strict)?
        \sfrom
        \s(?:
        (?P<L3T1_ruleSourceAny>any) # from any
        # from ip-securitygroup-13
        | (?:addrset\s+(?P<L3T1_ruleSourceAddrset1>\S+))
        # from not ip-securitygroup-13
        | (?P<L3T1_RuleSourceNegated>not)\s+addrset\s+(?P<L3T1_ruleSourceAddrset2>\S+)
        # from ip xx.xx.xx.xx
        | (?:ip\s+(?P<L3T1_ruleSourceAddrset3>\S+))
        # from not ip xx.xx.xx.xx
        | (?P<L3T1_RuleSourceNegated1>not)\s+ip\s+(?P<L3T1_ruleSourceAddrset4>\S+)
        )
        (?:\s+port\s+(?P<L3T1_RuleSourcePort>\d*(\-?\d*)?))?
        \sto
        \s(?:
        (?P<L3T1_ruleDestinationAny>any) # to any
        # to mac-securitygroup-13
        | (?:addrset\s+(?P<L3T1_ruleDestinationAddrset1>\S+))
        # to not mac-securitygroup-13
        | (?P<L3T1_RuleDestinationNegated>not)\s+addrset\s+(?P<L3T1_ruleDestinationAddrset2>\S+)
        # to ip xx.xx.xx.xx
        | (?:ip\s+(?P<L3T1_ruleDestinationAddrset3>\S+))
        # from not ip xx.xx.xx.xx
        | (?P<L3T1_RuleDestinationNegated1>not)\s+ip\s+(?P<L3T1_ruleDestinationAddrset4>\S+)
        )

        (?:\s+port\s+
        (?:
            (?P<L3T1_RuleDestinationPort>\d*(\-?\d*)?) | (?:\{(?P<L3T1_RuleDestinationPort1>.*)\})
        )
        )?
        # with attribute addrset attr_1092_1_APP_ID
        (?:\s+with\s+attribute\s+addrset\s+(?P<L3T1_ruleAttribute>\S+))?
        \s(?P<L3T1_ruleAction>\S+) # accept|drop|punt
        (?:\s+with\s+(?P<L3T1_ruleLogging>log))? # with log
        (?:\s+as\s+(?P<L3T1_ruleALG>\S+))? # as ftp
        (?:\s+tag\s+\'(?P<L3T1_ruleTag>.*)\')? # tag 'insert_witty_tag_here'
        \;$)
        # endregion
        # ##########################################################################
        # region L3 Rules (ICMP Protocol rules)
        | (?:
        ^(\s+)?rule
        \s+(?P<L3T2_ruleid>\d*)
        \sat
        \s(?P<L3T2_rulePosition>\d*)
        \s(?P<L3T2_ruleDirection>\S+)
        (?:\s(?P<L3T2_ruleAddressFamily>\S+))?
        \sprotocol
        \s(?:
            (?:
            (?:ipv6-)?
            (?P<L3T2_ruleProtocolIcmp>icmp)
            (?:
                \s+(icmptype|typecode)
                \s+(?P<L3T2_ruleProtocolIcmpType>[\d:]*)
            )?
            )
            | (?:
                (?:ipv6-)?
                (?P<L3T2_ruleProtocolIcmp1>icmp)
                (?:\s+stateless)?
            )
            | (?:
                (?:ipv6-)?
                (?P<L3T2_ruleProtocolIcmp2>icmp)
                \s+with
                # (?:\s+stateless)?
                (?:\s+\{stateless\,\s+(icmptype|typecode)\s+(?P<L3T2_ruleProtocolIcmpType1>[\d:]*)\})
            )
        )
        \sfrom
        \s(?:
        (?P<L3T2_ruleSourceAny>any) # from any
        # from ip-securitygroup-13
        | (?:addrset\s+(?P<L3T2_ruleSourceAddrset1>\S+))
        # from not ip-securitygroup-13
        | (?P<L3T2_RuleSourceNegated>not)\s+addrset\s+(?P<L3T2_ruleSourceAddrset2>\S+)
        # from ip xx.xx.xx.xx
        | (?:ip\s+(?P<L3T2_ruleSourceAddrset3>\S+))
        # from not ip xx.xx.xx.xx
        | (?P<L3T2_RuleSourceNegated1>not)\s+ip\s+(?P<L3T2_ruleSourceAddrset4>\S+)
        )
        \sto
        \s(?:
        (?P<L3T2_ruleDestinationAny>any) # to any
        # to ip-securitygroup-13
        | (?:addrset\s+(?P<L3T2_ruleDestinationAddrset1>\S+))
        # to not ip-securitygroup-13
        | (?P<L3T2_RuleDestinationNegated>not)\s+addrset\s+(?P<L3T2_ruleDestinationAddrset2>\S+)
        # to ip xx.xx.xx.xx
        | (?:ip\s+(?P<L3T2_ruleDestinationAddrset3>\S+))
        # from not ip xx.xx.xx.xx
        | (?P<L3T2_RuleDestinationNegated1>not)\s+ip\s+(?P<L3T2_ruleDestinationAddrset4>\S+)
        )
        # with attribute addrset attr_1092_1_APP_ID
        (?:\s+with\s+attribute\s+addrset\s+(?P<L3T2_ruleAttribute>\S+))?
        \s(?P<L3T2_ruleAction>\S+) # accept|drop|punt
        (?:\s+with\s+(?P<L3T2_ruleLogging>log))? # with log
        (?:\s+tag\s+\'(?P<L3T2_ruleTag>.*)\')? # tag 'insert_witty_tag_here'
        (?:\s+as\s+(?P<L3T2_ruleALG>\S+))? # as ftp
        \;$)
        # endregion
    ) #Close Non Capturing Parenthesis
    """

    REGEX_RULE_MATCH = re.compile(REGEX_RULE_STRING, re.VERBOSE)
    REGEX_IGNORE_STRING = r"""vsipioctl|generation number|realization time|Filter rules"""
    REGEX_IGNORE = re.compile(REGEX_IGNORE_STRING)

    def __init__(self, file_name, debug):
        self.genericParsedRuleset = collections.OrderedDict()
        self.serviceParsedRuleset = collections.OrderedDict()
        self.appliedto_dict = collections.OrderedDict()
        self.parseErrors = []
        self.debug = debug
        self.file_name = file_name
        self.rules_file = open(self.file_name, 'r')
        self.load_ruleset(self.rules_file)
        self.close()

    def close(self):
        if self.rules_file:
            self.rules_file.close()
            self.rules_file = None

    def get_serviceParsedRuleset(self):
        return self.serviceParsedRuleset

    def get_genericParsedRuleset(self):
        return self.genericParsedRuleset

    def dump_serviceParsedRuleset(self):
        print(json.dumps(self.serviceParsedRuleset, ensure_ascii=False, indent=4))

    def dump_genericParsedRuleset(self):
        print(json.dumps(self.genericParsedRuleset, ensure_ascii=False, indent=4))

    def dump_serviceParsedRuleset_file(self, directory, prefix):
        with open('%s/%sservice_parsed_rules.json' % (directory, prefix), 'w', encoding='utf-8') as f:
            json.dump(self.serviceParsedRuleset, f,
                      ensure_ascii=False, indent=4)

    def dump_genericParsedRuleset_file(self, directory, prefix):
        with open('%s/%sgeneric_parsed_rules.json' % (directory, prefix), 'w', encoding='utf-8') as f:
            json.dump(self.genericParsedRuleset, f,
                      ensure_ascii=False, indent=4)

    def parse_errors(self, directory, prefix):
        if len(self.parseErrors) >= 1:
            print('\n\n ********** PARSE ERRORS (%i) FOUND **********\n' %
                  (len(self.parseErrors)))

            with open('%s/%sparse_errors.log' % (directory, prefix), 'w', encoding='utf-8') as errorLogFile:
                for line in self.parseErrors:
                    errorLogFile.write('%s\n' % line)

            print('Parse errors have been saved to %s/%sparse_errors.log\n' %
                  (directory, prefix))

    def add_new_ruleid(self, ruleid, type):
        if type.lower() == 'appliedto' or type.lower() == 'both':
            if ruleid not in self.appliedto_dict:
                self.appliedto_dict[ruleid] = []
        if type.lower() == 'services' or type.lower() == 'both':
            if ruleid not in self.serviceParsedRuleset:
                self.serviceParsedRuleset[ruleid] = {'total': 0, 'total_tcp': 0, 'total_udp': 0,
                                                     'total_icmp': 0, 'total_igmp': 0, 'total_gre': 0, 'total_non_port': 0,
                                                     'total_alg': 0, 'total_internal': 0, 'original_rules': [],
                                                     'optimized_service_tcp': [], 'optimized_service_udp': [],
                                                     'optimized_service_other': []}
        if type.lower() == 'both':
            if ruleid not in self.genericParsedRuleset:
                self.genericParsedRuleset[ruleid] = {'original_rules': []}

    def add_rule_source(self, ruleid, matchgroup):
        source = matchgroup.group('L2T1_ruleSourceAny') or \
            matchgroup.group('L2T1_ruleSourceAddrset1') or \
            matchgroup.group('L2T1_ruleSourceAddrset2') or \
            matchgroup.group('L3T0_ruleSourceAny') or \
            matchgroup.group('L3T0_ruleSourceAddrset1') or \
            matchgroup.group('L3T0_ruleSourceAddrset2') or \
            matchgroup.group('L3T0_ruleSourceAddrset3') or \
            matchgroup.group('L3T0_ruleSourceAddrset4') or \
            matchgroup.group('L3T1_ruleSourceAny') or \
            matchgroup.group('L3T1_ruleSourceAddrset1') or \
            matchgroup.group('L3T1_ruleSourceAddrset2') or \
            matchgroup.group('L3T1_ruleSourceAddrset3') or \
            matchgroup.group('L3T1_ruleSourceAddrset4') or \
            matchgroup.group('L3T2_ruleSourceAny') or \
            matchgroup.group('L3T2_ruleSourceAddrset1') or \
            matchgroup.group('L3T2_ruleSourceAddrset2') or \
            matchgroup.group('L3T2_ruleSourceAddrset3') or \
            matchgroup.group('L3T2_ruleSourceAddrset4')
        self.genericParsedRuleset[ruleid]['source'] = source

    def add_rule_source_negate(self, ruleid, matchgroup):
        negate = None
        negate = matchgroup.group('L2T1_RuleSourceNegated') or \
            matchgroup.group('L3T0_RuleSourceNegated') or \
            matchgroup.group('L3T0_RuleSourceNegated1') or \
            matchgroup.group('L3T1_RuleSourceNegated') or \
            matchgroup.group('L3T1_RuleSourceNegated1') or \
            matchgroup.group('L3T2_RuleSourceNegated') or \
            matchgroup.group('L3T2_RuleSourceNegated1')
        if negate is not None:
            self.genericParsedRuleset[ruleid]['source_negated'] = True
        else:
            self.genericParsedRuleset[ruleid]['source_negated'] = False

    def add_rule_source_type(self, ruleid, matchgroup):
        if matchgroup.group('L2T1_ruleSourceAny') or \
                matchgroup.group('L3T0_ruleSourceAny') or \
                matchgroup.group('L3T1_ruleSourceAny') or \
                matchgroup.group('L3T2_ruleSourceAny'):
            fieldType = 'any'
        elif matchgroup.group('L3T0_ruleSourceAddrset1') or \
                matchgroup.group('L3T0_ruleSourceAddrset2') or \
                matchgroup.group('L3T1_ruleSourceAddrset1') or \
                matchgroup.group('L3T1_ruleSourceAddrset2') or \
                matchgroup.group('L3T2_ruleSourceAddrset1') or \
                matchgroup.group('L3T2_ruleSourceAddrset2'):
            fieldType = 'addrset'
        elif matchgroup.group('L3T0_ruleSourceAddrset3') or \
                matchgroup.group('L3T1_ruleSourceAddrset3') or \
                matchgroup.group('L3T2_ruleSourceAddrset3') or \
                matchgroup.group('L3T0_ruleSourceAddrset4') or \
                matchgroup.group('L3T1_ruleSourceAddrset4') or \
                matchgroup.group('L3T2_ruleSourceAddrset4'):
            fieldType = 'ip'
        else:
            print('RULEID: %s - cant match source type' % (ruleid))
            fieldType = 'None'
        self.genericParsedRuleset[ruleid]['source_type'] = fieldType

    def add_rule_destination(self, ruleid, matchgroup):
        destination = matchgroup.group('L2T1_ruleDestinationAny') or \
            matchgroup.group('L2T1_ruleDestinationAddrset1') or \
            matchgroup.group('L2T1_ruleDestinationAddrset2') or \
            matchgroup.group('L3T0_ruleDestinationAny') or \
            matchgroup.group('L3T0_ruleDestinationAddrset1') or \
            matchgroup.group('L3T0_ruleDestinationAddrset2') or \
            matchgroup.group('L3T0_ruleDestinationAddrset3') or \
            matchgroup.group('L3T0_ruleDestinationAddrset4') or \
            matchgroup.group('L3T1_ruleDestinationAny') or \
            matchgroup.group('L3T1_ruleDestinationAddrset1') or \
            matchgroup.group('L3T1_ruleDestinationAddrset2') or \
            matchgroup.group('L3T1_ruleDestinationAddrset3') or \
            matchgroup.group('L3T1_ruleDestinationAddrset4') or \
            matchgroup.group('L3T2_ruleDestinationAny') or \
            matchgroup.group('L3T2_ruleDestinationAddrset1') or \
            matchgroup.group('L3T2_ruleDestinationAddrset2') or \
            matchgroup.group('L3T2_ruleDestinationAddrset3') or \
            matchgroup.group('L3T2_ruleDestinationAddrset4')
        self.genericParsedRuleset[ruleid]['destination'] = destination

    def add_rule_destination_negate(self, ruleid, matchgroup):
        negate = None
        negate = matchgroup.group('L2T1_RuleDestinationNegated') or \
            matchgroup.group('L3T0_RuleDestinationNegated') or \
            matchgroup.group('L3T0_RuleDestinationNegated1') or \
            matchgroup.group('L3T1_RuleDestinationNegated') or \
            matchgroup.group('L3T1_RuleDestinationNegated1') or \
            matchgroup.group('L3T2_RuleDestinationNegated') or \
            matchgroup.group('L3T2_RuleDestinationNegated1')
        if negate is not None:
            self.genericParsedRuleset[ruleid]['destination_negated'] = True
        else:
            self.genericParsedRuleset[ruleid]['destination_negated'] = False

    def add_rule_destination_type(self, ruleid, matchgroup):
        if matchgroup.group('L2T1_ruleDestinationAny') or \
                matchgroup.group('L3T0_ruleDestinationAny') or \
                matchgroup.group('L3T1_ruleDestinationAny') or \
                matchgroup.group('L3T2_ruleDestinationAny'):
            fieldType = 'any'
        elif matchgroup.group('L3T0_ruleDestinationAddrset1') or \
                matchgroup.group('L3T0_ruleDestinationAddrset2') or \
                matchgroup.group('L3T1_ruleDestinationAddrset1') or \
                matchgroup.group('L3T1_ruleDestinationAddrset2') or \
                matchgroup.group('L3T2_ruleDestinationAddrset1') or \
                matchgroup.group('L3T2_ruleDestinationAddrset2'):
            fieldType = 'addrset'
        elif matchgroup.group('L3T0_ruleDestinationAddrset3') or \
                matchgroup.group('L3T1_ruleDestinationAddrset3') or \
                matchgroup.group('L3T2_ruleDestinationAddrset3') or \
                matchgroup.group('L3T0_ruleDestinationAddrset4') or \
                matchgroup.group('L3T1_ruleDestinationAddrset4') or \
                matchgroup.group('L3T2_ruleDestinationAddrset4'):
            fieldType = 'ip'
        else:
            print('RULEID: %s - cant match destination type' % (ruleid))
            fieldType = 'None'
        self.genericParsedRuleset[ruleid]['destination_type'] = fieldType

    def add_rule_protocol(self, ruleid, matchgroup):
        data = matchgroup.group('L2T1_ruleProtocol') or \
            matchgroup.group('L3T0_ruleProtocol') or \
            matchgroup.group('L3T1_ruleProtocol') or \
            matchgroup.group('L3T2_ruleProtocolIcmp') or \
            matchgroup.group('L3T2_ruleProtocolIcmp1') or \
            matchgroup.group('L3T2_ruleProtocolIcmp2')
        self.genericParsedRuleset[ruleid]['protocol'] = data

    def process_tcp_service(self, ruleid, matchgroup):
        if matchgroup.group('L3T1_ruleProtocol') == 'tcp' and not matchgroup.group('L3T1_ruleALG') and not matchgroup.group('L3T1_ruleInternal') and not matchgroup.group('L3T1_ruleAttribute') and not matchgroup.group('L3T1_RuleSourcePort'):
            self.serviceParsedRuleset[ruleid]['total_tcp'] = self.serviceParsedRuleset[ruleid]['total_tcp'] + 1

            # set a variable for the number of entries. Set this to one by default, that way we can keep a track
            # of what we are adding to the service. NSX-v services have a limit of 15 entries, but a range
            # counts as 2, so its not as simple as just counting the number of entries in the list.
            entryWeightToAdd = 1

            position = matchgroup.group('L3T1_rulePosition')
            if self.debug:
                print("RuleID: %s; Position: %s; Eligible for optimization (TCP Port)" %
                      (ruleid, position))

            if matchgroup.group('L3T1_RuleDestinationPort') or matchgroup.group('L3T1_RuleDestinationPort1'):
                # first determine if we are working with a port range or not
                destinationPort = matchgroup.group(
                    'L3T1_RuleDestinationPort') or matchgroup.group('L3T1_RuleDestinationPort1')
                destinationPort = destinationPort.split(',')
                for item in destinationPort:
                    item = item.lstrip()
                    entryWeightToAdd = utils.check_entry_weight(item)

                    serviceIndex = utils.check_list_space(
                        self.serviceParsedRuleset[ruleid]['optimized_service_tcp'], entryWeightToAdd)

                    # As there is no existing service list to append the entry to, a new list is appended with
                    # the port (item), otherwise the entry is added to the appropriate list via the index specified.
                    if serviceIndex is None:
                        if not utils.check_exists_nested(self.serviceParsedRuleset[ruleid]['optimized_service_tcp'], item):
                            self.serviceParsedRuleset[ruleid]['optimized_service_tcp'].append(
                                [item])
                            if self.debug:
                                print("RuleID: %s; Position: %s; Item: TCP %s: Starting new port listing." %
                                      (ruleid, position, item))
                        else:
                            if self.debug:
                                print("RuleID: %s; Position: %s; Item: TCP %s: Duplicate port detected." %
                                      (ruleid, position, item))
                    else:
                        if not utils.check_exists_nested(self.serviceParsedRuleset[ruleid]['optimized_service_tcp'], item):
                            utils.append_unique(
                                self.serviceParsedRuleset[ruleid]['optimized_service_tcp'][serviceIndex], item)
                            if self.debug:
                                print("RuleID: %s; Position: %s; Item: TCP %s: Adding to existing port listing." %
                                      (ruleid, position, item))
                        else:
                            if self.debug:
                                print("RuleID: %s; Position: %s; Item: TCP %s: Duplicate port detected." %
                                      (ruleid, position, item))
        elif matchgroup.group('L3T1_ruleProtocol') == 'tcp' and not matchgroup.group('L3T1_ruleALG') and not matchgroup.group('L3T1_ruleInternal'):
            self.serviceParsedRuleset[ruleid]['total_non_port'] = self.serviceParsedRuleset[ruleid]['total_non_port'] + 1

            if self.debug:
                print("RuleID: %s; Position: %s; Non-Eligible Rule" %
                      (ruleid, matchgroup.group('L3T1_rulePosition')))

    def process_udp_service(self, ruleid, matchgroup):
        if matchgroup.group('L3T1_ruleProtocol') == 'udp' and not matchgroup.group('L3T1_ruleALG') and not matchgroup.group('L3T1_ruleInternal') and not matchgroup.group('L3T1_ruleAttribute') and not matchgroup.group('L3T1_RuleSourcePort'):
            self.serviceParsedRuleset[ruleid]['total_udp'] = self.serviceParsedRuleset[ruleid]['total_udp'] + 1

            # set a variable for the number of entries. Set this to one by default, that way we can keep a track
            # of what we are adding to the service. NSX-v services have a limit of 15 entries, but a range
            # counts as 2, so its not as simple as just counting the number of entries in the list.
            entryWeightToAdd = 1

            position = matchgroup.group('L3T1_rulePosition')
            if self.debug:
                print("RuleID: %s; Position: %s; Eligible for optimization (UDP Port)" %
                      (ruleid, position))

            if matchgroup.group('L3T1_RuleDestinationPort') or matchgroup.group('L3T1_RuleDestinationPort1'):

                # first determine if we are working with a port range or not
                destinationPort = matchgroup.group(
                    'L3T1_RuleDestinationPort') or matchgroup.group('L3T1_RuleDestinationPort1')
                destinationPort = destinationPort.split(',')
                for item in destinationPort:
                    item = item.lstrip()
                    entryWeightToAdd = utils.check_entry_weight(item)

                    serviceIndex = utils.check_list_space(
                        self.serviceParsedRuleset[ruleid]['optimized_service_udp'], entryWeightToAdd)

                    if serviceIndex is None:
                        if not utils.check_exists_nested(self.serviceParsedRuleset[ruleid]['optimized_service_udp'], item):
                            self.serviceParsedRuleset[ruleid]['optimized_service_udp'].append(
                                [item])
                            if self.debug:
                                print("RuleID: %s; Position: %s; Item: UDP %s: Starting new port listing." %
                                      (ruleid, position, item))
                        else:
                            if self.debug:
                                print("RuleID: %s; Position: %s; Item: UDP %s: Duplicate port detected." %
                                      (ruleid, position, item))
                    else:
                        if not utils.check_exists_nested(self.serviceParsedRuleset[ruleid]['optimized_service_udp'], item):
                            utils.append_unique(
                                self.serviceParsedRuleset[ruleid]['optimized_service_udp'][serviceIndex], item)
                            if self.debug:
                                print("RuleID: %s; Position: %s; Item: UDP %s: Adding to existing port listing." %
                                      (ruleid, position, item))
                        else:
                            if self.debug:
                                print("RuleID: %s; Position: %s; Item: UDP %s: Duplicate port detected." %
                                      (ruleid, position, item))

        elif matchgroup.group('L3T1_ruleProtocol') == 'udp' and not matchgroup.group('L3T1_ruleALG') and not matchgroup.group('L3T1_ruleInternal'):
            self.serviceParsedRuleset[ruleid]['total_non_port'] = self.serviceParsedRuleset[ruleid]['total_non_port'] + 1
            if self.debug:
                print("RuleID: %s; Position: %s; Non-Eligible Rule" %
                      (ruleid, matchgroup.group('L3T1_rulePosition')))

    def process_icmp(self, ruleid, matchgroup):
        if matchgroup.group('L3T2_ruleid'):
            self.serviceParsedRuleset[ruleid]['total_icmp'] = self.serviceParsedRuleset[ruleid]['total_icmp'] + 1
            self.serviceParsedRuleset[ruleid]['total_non_port'] = self.serviceParsedRuleset[ruleid]['total_non_port'] + 1

    def process_non_optimized(self, ruleid, matchgroup):
        # Un-optimizable (is this even a word) rules
        if matchgroup.group('L3T0_ruleid'):
            self.serviceParsedRuleset[ruleid]['total_non_port'] = self.serviceParsedRuleset[ruleid]['total_non_port'] + 1
            if matchgroup.group('L3T0_ruleProtocol') == 'igmp':
                self.serviceParsedRuleset[ruleid]['total_igmp'] = self.serviceParsedRuleset[ruleid]['total_igmp'] + 1
            if matchgroup.group('L3T0_ruleProtocol') == 'gre':
                self.serviceParsedRuleset[ruleid]['total_gre'] = self.serviceParsedRuleset[ruleid]['total_gre'] + 1

    def increase_rule_count(self, ruleid):
        # Increase the total rule count
        self.serviceParsedRuleset[ruleid]['total'] = self.serviceParsedRuleset[ruleid]['total'] + 1

    def increase_internal_count(self, ruleid, matchgroup):
        if matchgroup.group('L3T1_ruleInternal'):
            self.serviceParsedRuleset[ruleid]['total_internal'] = self.serviceParsedRuleset[ruleid]['total_internal'] + 1

    def increase_alg_count(self, ruleid, matchgroup):
        if matchgroup.group('L3T1_ruleALG'):
            self.serviceParsedRuleset[ruleid]['total_alg'] = self.serviceParsedRuleset[ruleid]['total_alg'] + 1

            # TODO: Need to dedup this. A Rule may add ftp twice
            utils.append_unique(
                self.serviceParsedRuleset[ruleid]['optimized_service_other'], matchgroup.group('L3T1_ruleALG'))

    def add_raw_rule(self, line, ruleid):
        """
        Adds the original rule to the dictionary for forensic purposes
        """
        self.serviceParsedRuleset[ruleid]['original_rules'].append(line)
        self.genericParsedRuleset[ruleid]['original_rules'].append(line)

    def load_ruleset(self, fileObject):
        print('  --> Parsing rules')
        processingCounter = 0
        startTime = datetime.now()

        for i, line in enumerate(fileObject):
            line = line.rstrip()

            if line:
                processingCounter += 1
                if not self.debug:
                    print(' ' * 80, end='\r')
                    print('  --> Processed %s lines.' %
                          processingCounter, end='\r')
                    sys.stdout.flush()

                ignorematch = re.search(self.REGEX_IGNORE, line)
                globalmatch = re.search(self.REGEX_RULE_MATCH, line)

                if globalmatch:
                    # if args.debug is True:
                    #     # This shows the disctionary of the matches
                    #     for k, v in globalmatch.groupdict().items():
                    #         print("key=%s;value=%s" % (k, v))

                    if globalmatch.group('L3T0_ruleid') or globalmatch.group('L3T1_ruleid') or globalmatch.group('L3T2_ruleid'):
                        ruleid = globalmatch.group('L3T0_ruleid') or globalmatch.group(
                            'L3T1_ruleid') or globalmatch.group('L3T2_ruleid')
                        self.add_new_ruleid(ruleid, "Both")

                        # region Generic_rule_parsing
                        self.add_rule_source_negate(ruleid, globalmatch)
                        self.add_rule_source_type(ruleid, globalmatch)
                        self.add_rule_source(ruleid, globalmatch)
                        self.add_rule_destination_negate(ruleid, globalmatch)
                        self.add_rule_destination_type(ruleid, globalmatch)
                        self.add_rule_destination(ruleid, globalmatch)
                        self.add_rule_protocol(ruleid, globalmatch)
                        # endregion

                        # region Services_rule_parsing
                        self.increase_rule_count(ruleid)
                        self.add_raw_rule(line, ruleid)
                        self.increase_internal_count(ruleid, globalmatch)
                        self.increase_alg_count(ruleid, globalmatch)
                        self.process_tcp_service(ruleid, globalmatch)
                        self.process_udp_service(ruleid, globalmatch)
                        self.process_icmp(ruleid, globalmatch)
                        self.process_non_optimized(ruleid, globalmatch)
                        # endregion

                elif ignorematch:
                    pass
                else:
                    self.parseErrors.append(line)
                    pass
        finishTime = datetime.now() - startTime
        print('  --> Processed %s lines in %s' %
              (processingCounter, finishTime))


class AnalyzeServices:
    """
    This class is usead to calculate the statistics of the parsed rules
    """

    total_rules_count = 0
    total_rules_current_tcp = 0
    total_rules_current_udp = 0
    total_rules_current_non_port = 0
    total_rules_current_alg = 0
    total_rules_current_internal = 0
    total_rule_optimized_servicelists_tcp = 0
    total_rule_optimized_servicelists_udp = 0

    def __init__(self, outputdir, prefix, dictObject, debug):
        self.OUTPUTDIR = outputdir
        self.PREFIX = prefix
        self.RULESET = dictObject
        self.debug = debug

    def generate_csv(self):
        with open('%s/%sservice_data.csv' % (self.OUTPUTDIR, self.PREFIX), 'w', encoding='utf-8') as csv_file:
            csv_writer = csv.writer(csv_file, delimiter=',')
            header = ['RULE_ID', 'TOTAL_L3_RULES', 'TOTAL_NON_PORT_RULES',
                      'TOTAL_ALG_RULES', 'TOTAL_INTERNAL_RULES', 'TOTAL_L3_TCP_RULES',
                      'TOTAL_L3_UDP_RULES', 'TOTAL_L3_TCP_RULES_OPTIMIZED',
                      'TOTAL_L3_UDP_RULES_OPTIMIZED']
            csv_writer.writerow(header)

            for k, v in self.RULESET.items():
                self.total_rules_count += self.RULESET[k]['total']
                tcp_optimization_ratio = math.ceil(
                    self.RULESET[k]['total_tcp'] / 15)
                udp_optimization_ratio = math.ceil(
                    self.RULESET[k]['total_udp'] / 15)
                self.total_rules_current_non_port = self.total_rules_current_non_port + \
                    self.RULESET[k]['total_non_port']

                self.total_rules_current_alg = self.total_rules_current_alg + \
                    self.RULESET[k]['total_alg']

                self.total_rules_current_internal = self.total_rules_current_internal + \
                    self.RULESET[k]['total_internal']

                if self.RULESET[k]['total_tcp'] > 0:
                    self.total_rules_current_tcp = self.total_rules_current_tcp + \
                        self.RULESET[k]['total_tcp']

                    self.total_rule_optimized_servicelists_tcp = self.total_rule_optimized_servicelists_tcp + \
                        len(self.RULESET[k]['optimized_service_tcp'])

                if self.RULESET[k]['total_udp'] > 0:
                    self.total_rules_current_udp = self.total_rules_current_udp + \
                        self.RULESET[k]['total_udp']

                    self.total_rule_optimized_servicelists_udp = self.total_rule_optimized_servicelists_udp + \
                        len(self.RULESET[k]['optimized_service_udp'])

                row = [k, self.RULESET[k]['total'], self.RULESET[k]['total_non_port'],
                       self.RULESET[k]['total_alg'], self.RULESET[k]['total_internal'],
                       self.RULESET[k]['total_tcp'], self.RULESET[k]['total_udp'],
                       len(self.RULESET[k]['optimized_service_tcp']),
                       len(self.RULESET[k]['optimized_service_udp'])]
                csv_writer.writerow(row)

    def generate_summary(self):

        total_eligible_rules = self.total_rules_count - self.total_rules_current_non_port - \
            self.total_rules_current_alg - self.total_rules_current_internal

        count_of_rule_after_optimization = self.total_rule_optimized_servicelists_tcp + \
            self.total_rule_optimized_servicelists_udp

        count_of_all_vnic_rules_after_optmization = count_of_rule_after_optimization + \
            self.total_rules_current_non_port + \
            self.total_rules_current_alg + self.total_rules_current_internal

        percent_reduction_total_l3_rules = (
            (self.total_rules_count - count_of_all_vnic_rules_after_optmization) / self.total_rules_count) * 100

        with open('%s/%sservice_summary.txt' %
                  (self.OUTPUTDIR, self.PREFIX), 'w', encoding='utf-8', newline='\n') as summary_file:
            summary_file.write('\n')
            summary_file.write('='*80)
            summary_file.write('\n  Management Plane')
            summary_file.write(
                "\n  --> Total individual rules (MP) = %s" % len(self.RULESET))

            summary_file.write('\n')
            summary_file.write('='*80)
            summary_file.write('\n  Data Plane - Services Analysis')
            summary_file.write("\n  --> vNic L3 rules eligible for services optimization: %s" %
                               total_eligible_rules)
            summary_file.write("\n  --> vNic optimization eligible L3 rules AFTER services optimization: %i" %
                               count_of_rule_after_optimization)

            summary_file.write('\n')
            summary_file.write('='*80)
            summary_file.write('\n  Data Plane - BEFORE Services Optimization')
            summary_file.write(
                "\n  --> Total L3 rules on vNIC (DP) = %s" % self.total_rules_count)
            summary_file.write("\n  --> Total L3 Non Port rules (DP) = %s" %
                               self.total_rules_current_non_port)
            summary_file.write("\n  --> Total L3 ALG rules (DP) = %s" %
                               self.total_rules_current_alg)
            summary_file.write("\n  --> Total L3 ALG Internal rules (DP) = %s" %
                               self.total_rules_current_internal)
            summary_file.write(
                "\n  --> Total TCP exploded rules (DP) = %s" % self.total_rules_current_tcp)
            summary_file.write(
                "\n  --> Total UDP exploded rules (DP) = %s" % self.total_rules_current_udp)

            summary_file.write('\n')
            summary_file.write('='*80)
            summary_file.write('\n  Data Plane - AFTER Optimization')
            summary_file.write("\n  --> Total L3 rules on vNIC (DP) = %i (%i%% decrease)" %
                               (count_of_all_vnic_rules_after_optmization, utils.percentage_decrease(self.total_rules_count,
                                                                                                     count_of_all_vnic_rules_after_optmization)))
            summary_file.write("\n  --> Total L3 Non Port rules (DP) = %s" %
                               self.total_rules_current_non_port)
            summary_file.write("\n  --> Total L3 ALG rules (DP) = %s" %
                               self.total_rules_current_alg)
            summary_file.write("\n  --> Total L3 ALG Internal rules (DP) = %s" %
                               self.total_rules_current_internal)
            summary_file.write("\n  --> Total TCP optimized services (DP) = %s" %
                               self.total_rule_optimized_servicelists_tcp)
            summary_file.write("\n  --> Total UDP optimized services (DP) = %s" %
                               self.total_rule_optimized_servicelists_udp)
            summary_file.write('\n')
            summary_file.write('='*80)

    def display_summary(self):
        with open('%s/%sservice_summary.txt' %
                  (self.OUTPUTDIR, self.PREFIX), 'r', encoding='utf-8') as summary_file:
            print(summary_file.read())


class AnalyzeAppliedTo:
    def __init__(self, address, outputdir, prefix, rules, addrsets):
        """
        Class to analyze rules which are applicable to a given address

        address = IP Address to use for applied to analysis
        outputdir = directory to store any files generated
        prefix = string to prefix any files generated
        rules = generic parsed ruleset from RulesParser.get_genericParsedRuleset()
        addrsets = parsed address sets from AddrsetParser.get_addrsets()
        """
        self.OUTPUTDIR = outputdir
        self.PREFIX = prefix
        self.RULESET = rules
        self.ADDRSET = addrsets
        self.ADDRESS = address
        self.L3OPTIMIZEDFILTER = []
        self.IRRELEVANTRULESFILTER = []

    def get_addrset_detail(self, name):
        if name.lower() == 'any':
            return 'any'
        else:
            return self.ADDRSET[name]

    def get_ip_object(self, data):
        """
        Returns an appropriate ipaddress object based on the input
        """
        if '/' in data:
            return ipaddress.ip_network(data)
        else:
            return ipaddress.ip_address(data)

    def dump_l3OptimizedRules_file(self, directory, prefix):
        with open('%s/%sl3Optimized_rules.txt' % (directory, prefix), 'w', encoding='utf-8') as f:
            for line in self.L3OPTIMIZEDFILTER:
                f.write("%s\n" % (line))

    def dump_genericParsedRuleset_file(self, directory, prefix):
        with open('%s/%sappliedto_generic_parsed_rules.txt' % (directory, prefix), 'w', encoding='utf-8') as f:
            json.dump(self.RULESET, f, ensure_ascii=False, indent=4)

    def check_multicast(self, ipObject):
        if ipObject.is_multicast is True:
            return True
        else:
            return False

    def check_zero_net(self, ipObject):
        """
        Zero networks are treated as global rules. Depending on the version on
        NSX being used, in the earlier versions it was perfectly valid to have a
        zero network address on the data plane. In the later versions on NSX,
        this behaviour was removed but still need to test against it.
        """
        if ipaddress.ip_address('0.0.0.0') in ipaddress.ip_network(ipObject):
            status = True
        elif ipaddress.ip_address('::0') in ipaddress.ip_network(ipObject):
            status = True
        else:
            status = False
        return status

    def exist_in(self, ruleid, address, field):
        """
        Given a rule id, will check the supplied address matches the supplied
        field (src/dst)
        """
        status = False
        fieldType = self.RULESET[ruleid]['%s_type' % (field)]
        fieldNegated = self.RULESET[ruleid]['%s_negated' % (field)]
        fieldData = self.RULESET[ruleid][field]
        if fieldType == 'any':
            status = True
        elif fieldType == 'ip':
            ip = self.get_ip_object(fieldData)
            if self.check_zero_net(ip) is True:
                status = True
            if type(ip) is ipaddress.IPv4Network or type(ip) is ipaddress.IPv6Network:
                if ipaddress.ip_address(address) in ip:
                    status = True
        elif fieldType == 'addrset':
            status = self.exist_in_addrset(
                address, self.RULESET[ruleid][field])

        return status

    def exist_in_addrset(self, address, addrset):
        """
        Checks a given address exists within an address set (supplied by name).
        This could be an exact IP match, or the address could exists within one
        of the networks
        """
        ip = ipaddress.ip_address(address)
        status = False
        if address in self.ADDRSET[addrset]:
            status = True

        if status is not True:
            for entry in addrset:
                if '/' in entry:
                    if ip in ipaddress.ip_network(entry):
                        status = True
        return status

    def exist_multicast(self, ruleid):
        """
        Check whether a multicast address exists in a rule. If it does, then we
        return True to signifiy that this rule should be treated as a global rule
        """
        multicastFound = False
        fields = ['source', 'destination']
        for field in fields:
            exists = False

            if self.RULESET[ruleid]['%s_type' % (field)] == 'ip':
                ipObject = self.get_ip_object(self.RULESET[ruleid][field])
                exists = self.check_multicast(ipObject)
                if exists is True:
                    multicastFound = exists

            if self.RULESET[ruleid]['%s_type' % (field)] == 'addrset':
                addrsetDetails = self.get_addrset_detail(
                    self.RULESET[ruleid][field])
                for entry in addrsetDetails:
                    ipObject = self.get_ip_object(entry)
                    exists = self.check_multicast(ipObject)
                    if exists is True:
                        multicastFound = exists
                pass

        return multicastFound

    def process_appliedTo(self):
        print('  --> Analyzing applied to:')
        startTime = datetime.now()
        appliedToCounter = 0
        irrelevantRuleCounter = 0

        for ruleid in self.RULESET.keys():
            L3Optimized = False

            # A rule which has a src/dst which is marked as negated will
            # automatically become a "global" rule and will appear on all the
            # filters, so we flag it so we can add it to the list of filtered rules
            if self.RULESET[ruleid]['source_negated'] == True or self.RULESET[ruleid]['destination_negated']:
                L3Optimized = True

            # A rule which has 'any' in the src/dst will also get marked as a
            # "global rule" and will appear on all the filters
            elif self.RULESET[ruleid]['source'] == 'any' or self.RULESET[ruleid]['destination'] == 'any':
                L3Optimized = True

            # A rule which has a multicast address in the src/dst (either via
            # raw ip or addrset) will also get marked as a "global rule" and
            # will appear on all the filters
            elif self.exist_multicast(ruleid):
                L3Optimized = True
            else:
                existsSrc = self.exist_in(ruleid, self.ADDRESS, 'source')
                existsDst = self.exist_in(ruleid, self.ADDRESS, 'destination')

                if existsSrc is True or existsDst is True:
                    L3Optimized = True

            if L3Optimized is True:
                for original_rule in self.RULESET[ruleid]['original_rules']:
                    self.RULESET[ruleid]['L3_match'] = True
                    self.L3OPTIMIZEDFILTER.append(original_rule)
                    appliedToCounter += 1
                    print(' ' * 80, end='\r')
                    print('  --> Data Plane rule matches (%s): %s' %
                          (self.ADDRESS, appliedToCounter), end='\r')
                    sys.stdout.flush()
            else:
                for original_rule in self.RULESET[ruleid]['original_rules']:
                    self.RULESET[ruleid]['L3_match'] = False
                    self.IRRELEVANTRULESFILTER.append(original_rule)
                    irrelevantRuleCounter += 1
        self.dump_genericParsedRuleset_file(self.OUTPUTDIR, self.PREFIX)
        finishTime = datetime.now() - startTime
        print('  ----> Data Plane rule matches (%s): %s' %
              (self.ADDRESS, appliedToCounter))
        print('  ----> Data Plane rule misses (%s) : %s' %
              (self.ADDRESS, irrelevantRuleCounter))
        print('  ----> Analyzing applied to: Completed in %s' % (finishTime))
