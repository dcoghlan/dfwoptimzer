import re
import json
from pprint import pprint
import math
import sys
import os
import collections
import argparse
import csv
from common import utils
import time

#
# TODO - Show the list of optimized rule IDs somewhere

parser = argparse.ArgumentParser(
    description='A script to perform some basic DFW Data Plane Layer3 Rule Optimization analysis.')
parser.add_argument(
    '-f', '--file', help='File containing output of vsipioctl getrules -f <filtername>', metavar='<path>', required=True)
parser.add_argument(
    '-p', '--prefix', help='Name to use for prefix of files generated by the program.', dest='prefix', required=True)
parser.add_argument(
    '-o', '--outputdir', help='Path for all output files/logs', nargs='?', default='./logs', dest='outputdir')
parser.add_argument('-d', '--debug', dest='debug', action='store_true')

args = parser.parse_args()

if args.debug is True:
    print('\n\n Debug Mode Enabled (Sleeping for 3 seconds so you can make sure you have a large scollback buffer lol) \n\n')
    time.sleep(3)

OUTPUTDIR = args.outputdir

utils.create_dir(OUTPUTDIR)
utils.validate_file(args.file)

prefix = '%s-' % (args.prefix)

REGEX_RULE_STRING = r"""(?: #Non Capturing Parenthesis
    # match the closing curly brace
    (^(?P<closingBracket>\}))
    # ruleset domain-c132380_L2 {
    | (?:^ruleset\s+(?P<L2_ruleset_name>\S+L2)\s+[{])
    # ruleset domain-c132380 {
    | (^ruleset\s+(?P<L3_ruleset_name>\S+)\s+[{])
    # STARTThe next parse finds L2 rules
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
      (?P<L3T0_ruleProtocol>any|igmp|gre|ipv6-crypt|sctp|ip)
    )
    (?:\s+stateless)?
    (?:\s+strict)?
    \sfrom
    \s(?:
      (?P<L3T0_ruleSourceAny>any) # from any
      # from mac-securitygroup-13
      | (?:addrset\s+(?P<L3T0_ruleSourceAddrset1>\S+))
      # from not mac-securitygroup-13
      | (?P<L3T0_RuleSourceNegated>not)\s+addrset\s+(?P<L3T0_ruleSourceAddrset2>\S+)
      # from ip xx.xx.xx.xx
      | (?:ip\s+(?P<L3T0_ruleSourceAddrset3>\S+))
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
    )
    # with attribute addrset attr_1092_1_APP_ID
    (?:\s+with\s+attribute\s+addrset\s+(?P<L3T0_ruleAttribute>\S+))?
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
      # from mac-securitygroup-13
      | (?:addrset\s+(?P<L3T1_ruleSourceAddrset1>\S+))
      # from not mac-securitygroup-13
      | (?P<L3T1_RuleSourceNegated>not)\s+addrset\s+(?P<L3T1_ruleSourceAddrset2>\S+)
      # from ip xx.xx.xx.xx
      | (?:ip\s+(?P<L3T1_ruleSourceAddrset3>\S+))
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
      # from mac-securitygroup-13
      | (?:addrset\s+(?P<L3T2_ruleSourceAddrset1>\S+))
      # from not mac-securitygroup-13
      | (?P<L3T2_RuleSourceNegated>not)\s+addrset\s+(?P<L3T2_ruleSourceAddrset2>\S+)
      # from ip xx.xx.xx.xx
      | (?:ip\s+(?P<L3T2_ruleSourceAddrset3>\S+))
    )
    \sto
    \s(?:
      (?P<L3T2_ruleDestinationAny>any) # to any
      # to mac-securitygroup-13
      | (?:addrset\s+(?P<L3T2_ruleDestinationAddrset1>\S+))
      # to not mac-securitygroup-13
      | (?P<L3T2_RuleDestinationNegated>not)\s+addrset\s+(?P<L3T2_ruleDestinationAddrset2>\S+)
      # to ip xx.xx.xx.xx
      | (?:ip\s+(?P<L3T2_ruleDestinationAddrset3>\S+))
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
REGEX_IGNORE = re.compile(
    "\ .#\ (generation|realization|ruleset|Filter\ rules)")


# Create main data structure
dataDict = collections.OrderedDict()
processingCounter = 0
parseErrors = []

for i, line in enumerate(open(args.file)):

    # Remove any trailing white space from the line.
    line = line.rstrip()

    if line:
        if args.debug is not True:
            processingCounter += 1
            print(' ' * 80, end='\r')
            print('Processed %s rules.' % processingCounter, end='\r')
            sys.stdout.flush()
        else:
            print('-'*80)
            print(line)

        ignorematch = re.search(REGEX_IGNORE, line)
        globalmatch = re.search(REGEX_RULE_MATCH, line)

        if globalmatch:
            if args.debug is True:
                # This shows the disctionary of the matches
                for k, v in globalmatch.groupdict().items():
                    print("key=%s;value=%s" % (k, v))

            if globalmatch.group('L3T0_ruleid') or globalmatch.group('L3T1_ruleid') or globalmatch.group('L3T2_ruleid'):
                ruleid = globalmatch.group('L3T0_ruleid') or globalmatch.group(
                    'L3T1_ruleid') or globalmatch.group('L3T2_ruleid')

                # If this is a new rule ID, then initialise an entry in the dictionary
                if ruleid not in dataDict:
                    dataDict[ruleid] = {'total': 0, 'total_tcp': 0, 'total_udp': 0,
                                        'total_icmp': 0, 'total_igmp': 0, 'total_gre': 0, 'total_non_port': 0,
                                        'total_alg': 0, 'total_internal': 0, 'original_rules': [],
                                        'optimized_service_tcp': [], 'optimized_service_udp': [],
                                        'optimized_service_other': []}

                # Increase the total rule count
                dataDict[ruleid]['total'] = dataDict[ruleid]['total'] + 1
                # Add the original rule to the dictionary for forensic purposes
                dataDict[ruleid]['original_rules'].append(line)

                if globalmatch.group('L3T1_ruleInternal'):
                    dataDict[ruleid]['total_internal'] = dataDict[ruleid]['total_internal'] + 1

                if globalmatch.group('L3T1_ruleALG'):
                    dataDict[ruleid]['total_alg'] = dataDict[ruleid]['total_alg'] + 1

                    utils.append_unique(
                        dataDict[ruleid]['optimized_service_other'], globalmatch.group('L3T1_ruleALG'))

                if globalmatch.group('L3T1_ruleProtocol') == 'tcp' and not globalmatch.group('L3T1_ruleALG') and not globalmatch.group('L3T1_ruleInternal'):
                    dataDict[ruleid]['total_tcp'] = dataDict[ruleid]['total_tcp'] + 1

                    # set a variable for the number of entries. Set this to one by default, that way we can keep a track
                    # of what we are adding to the service. NSX-v services have a limit of 15 entries, but a range
                    # counts as 2, so its not as simple as just counting the number of entries in the list.
                    entryWeightToAdd = 1

                    if globalmatch.group('L3T1_RuleDestinationPort') or globalmatch.group('L3T1_RuleDestinationPort1'):
                        # first determine if we are working with a port range or not
                        destinationPort = globalmatch.group(
                            'L3T1_RuleDestinationPort') or globalmatch.group('L3T1_RuleDestinationPort1')
                        destinationPort = destinationPort.split(',')
                        for item in destinationPort:
                            item = item.lstrip()
                            entryWeightToAdd = utils.check_entry_weight(item)

                            serviceIndex = utils.check_list_space(
                                dataDict[ruleid]['optimized_service_tcp'], entryWeightToAdd)

                            # As there is no existing service list to append the entry to, a new list is appended with
                            # the port (item), otherwise the entry is added to the appropriate list via the index specified.
                            if serviceIndex is None:
                                if not utils.check_exists_nested(dataDict[ruleid]['optimized_service_tcp'], item):
                                    dataDict[ruleid]['optimized_service_tcp'].append(
                                        [item])
                            else:
                                if not utils.check_exists_nested(dataDict[ruleid]['optimized_service_tcp'], item):
                                    utils.append_unique(
                                        dataDict[ruleid]['optimized_service_tcp'][serviceIndex], item)

                if globalmatch.group('L3T1_ruleProtocol') == 'udp' and not globalmatch.group('L3T1_ruleALG') and not globalmatch.group('L3T1_ruleInternal'):
                    dataDict[ruleid]['total_udp'] = dataDict[ruleid]['total_udp'] + 1

                    # set a variable for the number of entries. Set this to one by default, that way we can keep a track
                    # of what we are adding to the service. NSX-v services have a limit of 15 entries, but a range
                    # counts as 2, so its not as simple as just counting the number of entries in the list.
                    entryWeightToAdd = 1

                    if globalmatch.group('L3T1_RuleDestinationPort') or globalmatch.group('L3T1_RuleDestinationPort1'):
                        # first determine if we are working with a port range or not
                        destinationPort = globalmatch.group(
                            'L3T1_RuleDestinationPort') or globalmatch.group('L3T1_RuleDestinationPort1')
                        destinationPort = destinationPort.split(',')
                        for item in destinationPort:
                            item = item.lstrip()
                            entryWeightToAdd = utils.check_entry_weight(item)

                            serviceIndex = utils.check_list_space(
                                dataDict[ruleid]['optimized_service_udp'], entryWeightToAdd)

                            if serviceIndex is None:
                                if not utils.check_exists_nested(dataDict[ruleid]['optimized_service_udp'], item):
                                    dataDict[ruleid]['optimized_service_udp'].append(
                                        [item])
                            else:
                                if not utils.check_exists_nested(dataDict[ruleid]['optimized_service_udp'], item):
                                    utils.append_unique(
                                        dataDict[ruleid]['optimized_service_udp'][serviceIndex], item)

                if globalmatch.group('L3T2_ruleid'):
                    dataDict[ruleid]['total_icmp'] = dataDict[ruleid]['total_icmp'] + 1
                    dataDict[ruleid]['total_non_port'] = dataDict[ruleid]['total_non_port'] + 1

                # Un-optimizable (is this even a word) rules
                if globalmatch.group('L3T0_ruleid'):
                    dataDict[ruleid]['total_non_port'] = dataDict[ruleid]['total_non_port'] + 1
                    if globalmatch.group('L3T0_ruleProtocol') == 'igmp':
                        dataDict[ruleid]['total_igmp'] = dataDict[ruleid]['total_igmp'] + 1
                    if globalmatch.group('L3T0_ruleProtocol') == 'gre':
                        dataDict[ruleid]['total_gre'] = dataDict[ruleid]['total_gre'] + 1

        elif ignorematch:
            pass
        else:
            print("\nNO MATCH: %s" % (line))
            parseErrors.append(line)
            pass

# TODO: Flatten and sort the service list and re-create them.
# for k, v in dataDict.items():
#     dataDict[k]['optimized_service_tcp'].sort()
#     # print("key=%s;value=%s" % (k, v))

with open('%s/%sdata.json' % (OUTPUTDIR, prefix), 'w', encoding='utf-8') as f:
    json.dump(dataDict, f, ensure_ascii=False, indent=4)

if len(parseErrors) >= 1:
    print('\n\n ********** PARSE ERRORS (%i) FOUND **********\n\n' %
          (len(parseErrors)))
    with open('%s/%sparseErrors.log' % (OUTPUTDIR, prefix), 'w', encoding='utf-8') as errorLogFile:
        for line in parseErrors:
            errorLogFile.write('%s\n' % line)

total_rules_count = 0
total_rules_current_tcp = 0
total_rules_current_udp = 0
total_rules_current_non_port = 0
total_rules_current_alg = 0
total_rules_current_internal = 0
total_rule_optimized_servicelists_tcp = 0
total_rule_optimized_servicelists_udp = 0

with open('%s/%sdata.csv' % (OUTPUTDIR, prefix), 'w', encoding='utf-8') as csv_file:
    csv_writer = csv.writer(csv_file, delimiter=',')
    header = ['RULE_ID', 'TOTAL_L3_RULES', 'TOTAL_NON_PORT_RULES',
              'TOTAL_ALG_RULES', 'TOTAL_INTERNAL_RULES', 'TOTAL_L3_TCP_RULES',
              'TOTAL_L3_UDP_RULES', 'TOTAL_L3_TCP_RULES_OPTIMIZED',
              'TOTAL_L3_UDP_RULES_OPTIMIZED']
    csv_writer.writerow(header)

    for k, v in dataDict.items():
        total_rules_count += dataDict[k]['total']
        tcp_optimization_ratio = math.ceil(dataDict[k]['total_tcp'] / 15)
        udp_optimization_ratio = math.ceil(dataDict[k]['total_udp'] / 15)
        total_rules_current_non_port = total_rules_current_non_port + \
            dataDict[k]['total_non_port']

        total_rules_current_alg = total_rules_current_alg + \
            dataDict[k]['total_alg']

        total_rules_current_internal = total_rules_current_internal + \
            dataDict[k]['total_internal']

        if dataDict[k]['total_tcp'] > 0:
            total_rules_current_tcp = total_rules_current_tcp + \
                dataDict[k]['total_tcp']

            total_rule_optimized_servicelists_tcp = total_rule_optimized_servicelists_tcp + \
                len(dataDict[k]['optimized_service_tcp'])

        if dataDict[k]['total_udp'] > 0:
            total_rules_current_udp = total_rules_current_udp + \
                dataDict[k]['total_udp']

            total_rule_optimized_servicelists_udp = total_rule_optimized_servicelists_udp + \
                len(dataDict[k]['optimized_service_udp'])

        row = [k, dataDict[k]['total'], dataDict[k]['total_non_port'],
               dataDict[k]['total_alg'], dataDict[k]['total_internal'],
               dataDict[k]['total_tcp'], dataDict[k]['total_udp'],
               len(dataDict[k]['optimized_service_tcp']),
               len(dataDict[k]['optimized_service_udp'])]
        csv_writer.writerow(row)

total_eligible_rules = total_rules_count - total_rules_current_non_port - \
    total_rules_current_alg - total_rules_current_internal

count_of_rule_after_optimization = total_rule_optimized_servicelists_tcp + \
    total_rule_optimized_servicelists_udp

count_of_all_vnic_rules_after_optmization = count_of_rule_after_optimization + \
    total_rules_current_non_port + total_rules_current_alg + total_rules_current_internal

percent_reduction_total_l3_rules = (
    (total_rules_count - count_of_all_vnic_rules_after_optmization) / total_rules_count) * 100

print('='*80)
print('  Management Plane')
print("  --> Total individual rules (MP) = %s" % len(dataDict))

print('='*80)
print('  Data Plane - Analysis')
print("  --> vNic L3 rules eligible for optimization: %s" %
      total_eligible_rules)
print("  --> vNic optimization eligible L3 rules AFTER optimization: %i" %
      count_of_rule_after_optimization)

print('='*80)
print('  Data Plane - BEFORE Optimization')
print("  --> Total L3 rules on vNIC (DP) = %s" % total_rules_count)
print("  --> Total L3 Non Port rules (DP) = %s" %
      total_rules_current_non_port)
print("  --> Total L3 ALG rules (DP) = %s" %
      total_rules_current_alg)
print("  --> Total L3 ALG Internal rules (DP) = %s" %
      total_rules_current_internal)
print("  --> Total TCP exploded rules (DP) = %s" % total_rules_current_tcp)
print("  --> Total UDP exploded rules (DP) = %s" % total_rules_current_udp)

print('='*80)
print('  Data Plane - AFTER Optimization')
print("  --> Total L3 rules on vNIC (DP) = %i (%i%% decrease)" %
      (count_of_all_vnic_rules_after_optmization, utils.percentage_decrease(total_rules_count,
                                                                            count_of_all_vnic_rules_after_optmization)))
print("  --> Total L3 Non Port rules (DP) = %s" %
      total_rules_current_non_port)
print("  --> Total L3 ALG rules (DP) = %s" %
      total_rules_current_alg)
print("  --> Total L3 ALG Internal rules (DP) = %s" %
      total_rules_current_internal)
print("  --> Total TCP optimized services (DP) = %s" %
      total_rule_optimized_servicelists_tcp)
print("  --> Total UDP optimized services (DP) = %s" %
      total_rule_optimized_servicelists_udp)
print('='*80)