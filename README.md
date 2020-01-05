# NSX Distributed Firewall - Data Plane Optimizer and Analysis Tool

The NSX Distributed Firewall Data Plane Optimizer & Analysis Tool is designed to assist with identifying configuration programmed into the data plane of an ESXi host that is able to be optimized.

There are several configuration patterns, that when configured in the NSX Management Plane result in an un-optimised configuration in the data plane.

The tool has multiple modes which can be used to help understand how the configuration can be optmised and will some outputs which is representitive of a fully optmised configuration.

## Requirements

- Python 3.6.x

## Modes

### dfw_services

Parse the output of `vsipioctl getrules -f <filtername>` and perform some analysis in relation to rule explosion by way of the services configured on the rule in the Management Plane.

The dfw_services mode requires the following:

- `rules` - output of `vsipioctl getrules -f <filtername>` from a NSX-v host saved in a file accessible from where the python script is run.

- `prefix` - a string which will be prefixed to all the output files generated.

```
python3 dfwoptimizer/dfwoptimizer.py dfw_services --rules ./vsipioctl_rules_output.txt --prefix PROD_VM1
```

After the script has run, a summary will be displayed on the screen similar to the following.

```bash

  --> Parsing rules
  --> Processed 17242 lines in 0:00:01.859026

================================================================================
  Management Plane
  --> Total individual rules (MP) = 5228
================================================================================
  Data Plane - Services Analysis
  --> vNic L3 rules eligible for services optimization: 16310
  --> vNic optimization eligible L3 rules AFTER services optimization: 5947
================================================================================
  Data Plane - BEFORE Services Optimization
  --> Total L3 rules on vNIC (DP) = 17234
  --> Total L3 Non Port rules (DP) = 532
  --> Total L3 ALG rules (DP) = 169
  --> Total L3 ALG Internal rules (DP) = 223
  --> Total TCP exploded rules (DP) = 13821
  --> Total UDP exploded rules (DP) = 2489
================================================================================
  Data Plane - AFTER Optimization
  --> Total L3 rules on vNIC (DP) = 6871 (60% decrease)
  --> Total L3 Non Port rules (DP) = 532
  --> Total L3 ALG rules (DP) = 169
  --> Total L3 ALG Internal rules (DP) = 223
  --> Total TCP optimized services (DP) = 5081
  --> Total UDP optimized services (DP) = 866
================================================================================


 ********** PARSE ERRORS (1) FOUND **********

Parse errors have been saved to ./logs/PROD_VM1-parse_errors.log
```

- **Total individual rules (MP)**: The total number of rules (derived from the vNIC filter) that are configured on the Management Plane/UI for this particular vNIC.
- **vNic L3 rules eligible for services optimization**: The number of Layer 3 rules on the provided filter which have a TCP or UDP port configured which could potentially be optmized to use inline service ports on the Management Plane/UI.
- **vNic optimization eligible L3 rules AFTER services optimization**: If service optimization was applied to all the `vNic L3 rules eligible for services optimization` above, the number of rules on this filter would be reduced to this number.

#### dfw_services - Output Files

The following files are generated in the folder `./logs` by default.

- `<prefix>`-service_summary.txt

  - The contents of this file is used to generate the screen output above.

- `<prefix>`-service_data.csv

  - This file can be opened in Excel (or your spreadsheet application of your choice) and allows you to sort the data. The rules which will give you the best return on effort will be the ones with the highest figures in the `TOTAL_L3_TCP_RULES` and `TOTAL_L3_UDP_RULES` columns. You can then use the `RULE_ID` to correlate the rule back on the management plane to modify.
  - Example of a rule as shown in the csv file:

```
RULE_ID,TOTAL_L3_RULES,TOTAL_NON_PORT_RULES,TOTAL_ALG_RULES,TOTAL_INTERNAL_RULES,TOTAL_L3_TCP_RULES,TOTAL_L3_UDP_RULES,TOTAL_L3_TCP_RULES_OPTIMIZED,TOTAL_L3_UDP_RULES_OPTIMIZED
4525,24,0,1,1,13,9,1,1
```

- `<prefix>`-service_parsed_rules.json

  - This is a JSON formatted file which contains the internal data structure which is used to perform the analysis on the file provided. This file can be used to see what optimised services you should create for each rule. It must be noted that you shouldn't use this file blindly to create services based off of it. The rules as configured in the Management Plane may re-use existing services or service groups, so a change to 1 rule may in-fact update many rules as they all reference the same object.

  - For the optimised service lists that are presented in this file, the port lists have be de-duped as it is possible to have duplicate ports configured.
  - Example of a rule as shown in the json file:

```json
{
  "4525": {
    "total": 24,
    "total_tcp": 13,
    "total_udp": 9,
    "total_icmp": 0,
    "total_igmp": 0,
    "total_gre": 0,
    "total_non_port": 0,
    "total_alg": 1,
    "total_internal": 1,
    "original_rules": [
      "  rule 4525 at 5777 inout protocol tcp from addrset ip-securitygroup-2833 to addrset dst8187 port 137 accept with log;",
      "  rule 4525 at 5778 inout protocol tcp from addrset ip-securitygroup-2833 to addrset dst8187 port 138 accept with log;",
      "  rule 4525 at 5779 inout protocol tcp from addrset ip-securitygroup-2833 to addrset dst8187 port 53 accept with log;",
      "  rule 4525 at 5780 inout protocol udp from addrset ip-securitygroup-2833 to addrset dst8187 port 53 accept with log;",
      "  rule 4525 at 5781 inout protocol udp from addrset ip-securitygroup-2833 to addrset dst8187 port 135 accept with log;",
      "  rule 4525 at 5782 inout protocol tcp from addrset ip-securitygroup-2833 to addrset dst8187 port 88 accept with log;",
      "  rule 4525 at 5783 inout protocol udp from addrset ip-securitygroup-2833 to addrset dst8187 port 88 accept with log;",
      "  rule 4525 at 5784 inout protocol tcp from addrset ip-securitygroup-2833 to addrset dst8187 port 389 accept with log;",
      "  rule 4525 at 5785 inout protocol tcp from addrset ip-securitygroup-2833 to addrset dst8187 port 49152-65535 accept with log;",
      "  rule 4525 at 5786 inout protocol udp from addrset ip-securitygroup-2833 to addrset dst8187 port 389 accept with log;",
      "  rule 4525 at 5787 inout protocol tcp from addrset ip-securitygroup-2833 to addrset dst8187 port 636 accept with log;",
      "  rule 4525 at 5788 inout protocol tcp from addrset ip-securitygroup-2833 to addrset dst8187 port 445 accept with log;",
      "  rule 4525 at 5789 inout protocol tcp from addrset ip-securitygroup-2833 to addrset dst8187 port 3268 accept with log;",
      "  rule 4525 at 5790 inout protocol udp from addrset ip-securitygroup-2833 to addrset dst8187 port 445 accept with log;",
      "  rule 4525 at 5791 inout protocol tcp from addrset ip-securitygroup-2833 to addrset dst8187 port 135 accept with log as dcerpc;",
      "  # internal # rule 4525 at 5792 inout protocol tcp from addrset ip-securitygroup-2833 to addrset dst8187 port 135 accept with log;",
      "  rule 4525 at 5793 inout protocol udp from addrset ip-securitygroup-2833 to addrset dst8187 port 138 accept with log;",
      "  rule 4525 at 5794 inout protocol udp from addrset ip-securitygroup-2833 to addrset dst8187 port 137 accept with log;",
      "  rule 4525 at 5795 inout protocol tcp from addrset ip-securitygroup-2833 to addrset dst8187 port 139 accept with log;",
      "  rule 4525 at 5796 inout protocol tcp from addrset ip-securitygroup-2833 to addrset dst8187 port 123 accept with log;",
      "  rule 4525 at 5797 inout protocol udp from addrset ip-securitygroup-2833 to addrset dst8187 port 123 accept with log;",
      "  rule 4525 at 5798 inout protocol tcp from addrset ip-securitygroup-2833 to addrset dst8187 port 464 accept with log;",
      "  rule 4525 at 5799 inout protocol udp from addrset ip-securitygroup-2833 to addrset dst8187 port 464 accept with log;",
      "  rule 4525 at 5800 inout protocol tcp from addrset ip-securitygroup-2833 to addrset dst8187 port 3269 accept with log;"
    ],
    "optimized_service_tcp": [
      [
        "137",
        "138",
        "53",
        "88",
        "389",
        "49152-65535",
        "636",
        "445",
        "3268",
        "139",
        "123",
        "464",
        "3269"
      ]
    ],
    "optimized_service_udp": [
      ["53", "135", "88", "389", "445", "138", "137", "123", "464"]
    ],
    "optimized_service_other": ["dcerpc"]
  }
}
```

- `<prefix>`-parse_errors.log

  - If there are any parsing errors, these are logged to this file. Please log an issue and submit the contents of this file so the parsing can be enhanced.

### dfw_appliedto

This mode parses the rules and address sets configured on a filter and analyzes them against a user supplied IPv4 address (that usually represents the IP address of the vNIC) and produces a filtered list of data plane rules that are applicable to the vNIC.

The dfw_appliedto mode requires the following:

- `rules` - output of `vsipioctl getrules -f <filtername>` from a NSX-v host saved in a file accessible from where the python script is run.

- `addrsets` - output of `vsipioctl getaddrsets -f <filtername>` from a NSX-v host saved in a file accessible from where the python script is run.

- `prefix` - a string which will be prefixed to all the output files generated.

- `ipaddress` - a single IP address (IPv4 only) for which to compare to the supplied rules and address sets.

```bash
python3 dfwoptimizer/dfwoptimizer.py dfw_appliedto --rules ./vsipioctl_rules_output.txt --addrsets ./vsipioctl_addrsets_output.txt --prefix PROD_VM1 --ipaddress 10.38.181.157
```

After the script has run, a small summary will be displayed on the screen similar to the following:

```bash

  --> Parsing rules
  --> Processed 17242 lines in 0:00:01.715733
  --> Parsing address sets
  --> Processed 246138 entries from 4846 total address sets in 0:00:07.740228
  --> Analyzing applied to
  --> Data Plane rule matches (10.38.181.157): 220
  --> Data Plane rule misses (10.38.181.157) : 17014


 ********** PARSE ERRORS (1) FOUND **********

Parse errors have been saved to ./logs/PROD_VM1-parse_errors.log
```

- **Data Plane rule matches (ipaddress)**: The total number of data plane rules which are a match against the user supplied IP address. These are the only rules that can be possibly hit on the specificed filter.
- **Data Plane rule misses (ipaddress)**: The total number of data plane rules that DO NOT match the user supplied IP address. These rules will NEVER match the given IP address and are not required to be programmed onto this filter.

#### dfw_appliedto - Output Files

The following files are generated in the folder `./logs` by default.

- `<prefix>`-appliedto_generic_parsed_rules.json
  - This is a JSON formatted file which contains the generically parsed rules. Although the parser identifies all the fields, the output file only contains a subset of the complete rule information that is required to match the source and destination of the rule against the supplied IP address.

```json
{
  "8196": {
    "original_rules": [
      "  rule 8196 at 1 inout protocol tcp from addrset ip-ipset-24029 to addrset ip-securitygroup-6920 port 22 accept with log;",
      "  rule 8196 at 2 inout protocol tcp from addrset ip-ipset-24029 to addrset ip-securitygroup-6920 port 443 accept with log;"
    ],
    "source_negated": false,
    "source_type": "addrset",
    "source": "ip-ipset-24029",
    "destination_negated": false,
    "destination_type": "addrset",
    "destination": "ip-securitygroup-6920",
    "protocol": "tcp",
    "L3_match": false
  }
}
```

- `<prefix>`-l3Optimized_rules.txt

  - Contains just the rules that match the user supplied IP address. If the `Applied To` feature of the NSX Distributed firewall was configured appropriately, this is a representation of what the filter may look like.
  - Along with rules which are a match against the user supplied IP address, rules which utilise address sets that contain a match for the user supplied IP address will also appear in this file
  - Rules that use `any` in the source or destination will appear in this file.
  - Rules that contain a multicast address directly (or via an address set) will appear in this file.

- `<prefix>`-parse_errors.log

  - If there are any parsing errors, these are logged to this file. Please log an issue and submit the contents of this file so the parsing can be enhanced.
