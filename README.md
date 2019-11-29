# NSX Distributed Firewall - Data Plane Optimizer

Parse the output of `vsipioctl getrules -f <filtername>` and perform some analysis in relation to rule explosion by way of the services configured on the rule in the Management Plane.

## Requirements

- Python3
- output of `vsipioctl getrules -f <filtername>` from a NSX-v host saved in a file accessible from where the python script is run.

## How to run it

`python3 dfwoptimizer.py --prefixp test -f ../sample_data/OC3-6.4.5-15-10`

The `prefix` is a string which will be prefixed to all the output files and is required to run the script.

## Output

### OnScreen Display

- The following is an example of the output displayed on the screen

```bash
================================================================================
  Management Plane
  --> Total individual rules (MP) = 5317
================================================================================
  Data Plane - Analysis
  --> vNic L3 rules eligible for optimization: 15633
  --> vNic optimization eligible L3 rules AFTER optimization: 6011
================================================================================
  Data Plane - BEFORE
  --> Total L3 rules on vNIC (DP) = 16555
  --> Total L3 Non Port rules (DP) = 533
  --> Total L3 ALG rules (DP) = 167
  --> Total L3 ALG Internal rules (DP) = 222
  --> Total TCP exploded rules (DP) = 13155
  --> Total UDP exploded rules (DP) = 2478
================================================================================
  Breakdown of Optimized Rules
  --> Total L3 rules on vNIC (DP) = 6933
  --> Total L3 Non Port rules (DP) = 533
  --> Total L3 ALG rules (DP) = 167
  --> Total L3 ALG Internal rules (DP) = 222
  --> Total TCP optimized services (DP) = 5134
  --> Total UDP optimized services (DP) = 877
================================================================================
```

- **Total individual rules (MP)**: The total number of rules (derived from the vNIC filter) that are configured on the Management Plane/UI for this particular vNIC.
- **vNic L3 rules eligible for optimization**: The number of Layer 3 rules on the provided filter which have a TCP or UDP port configured which could potentially be optmized to use inline service ports on the Management Plane/UI.
- **vNic optimization eligible L3 rules AFTER optimization**: If service optimization was applied to all the `vNic L3 rules eligible for optimization` above, the number of rules on this filter would be reduced to this number.

### Output Files

The following files are generated in the folder `./logs` by default.

- `<prefix>`-data.csv

  - This file can be opened in Excel (or your spreadsheet application of your choice) and allows you to sort the data. The rules which will give you the best return on effort will be the ones with the highest figures in the `TOTAL_L3_TCP_RULES` and `TOTAL_L3_UDP_RULES` columns. You can then use the `RULE_ID` to correlate the rule back on the management plane to modify.
  - Example of a rule as shown in the csv file:

```
RULE_ID,TOTAL_L3_RULES,TOTAL_NON_PORT_RULES,TOTAL_ALG_RULES,TOTAL_INTERNAL_RULES,TOTAL_L3_TCP_RULES,TOTAL_L3_UDP_RULES,TOTAL_L3_TCP_RULES_OPTIMIZED,TOTAL_L3_UDP_RULES_OPTIMIZED
4525,24,0,1,1,13,9,1,1
```

- `<prefix>`-data.json

  - This is a JSON formatted file which contains the internal data structure which is used to perform the analysis on the file provided. This file can be used to see what optimised services you should create for each rule. It must be noted that you shouldn't use this file blindly to create services based off of it. The rules as configured in the Management Plane may re-use existing services or service groups, so a change to 1 rule may in-fact update many rules as they all reference the same object.

  - For the optimised service lists that are presented in this file, the port lists have be de-duped as it is possible to have duplicate ports configured.
  - Example of a rule as shown in the json file:

```
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
            [
                "53",
                "135",
                "88",
                "389",
                "445",
                "138",
                "137",
                "123",
                "464"
            ]
        ],
        "optimized_service_other": [
            "dcerpc"
        ]
    }
}
```

- `<prefix>`-parseErrors.log

  - If there are any parsing errors, these are logged to this file. Please log an issue and submit the contents of this file so the parsing can be enhanced.
