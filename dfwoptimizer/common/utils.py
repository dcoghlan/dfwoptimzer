import os
import sys


def validate_python():
    version = sys.version_info
    if version[0] < 3 or version[1] < 6:
        print("DFW Optimizer expects python 3.6 or above")
        sys.exit(1)


def create_dir(path):
    if not os.path.exists(path):
        os.makedirs(path)


def validate_file(file, debug=False):
    if debug is True:
        print("  --> validating path: %s" % (file))
    if not os.path.exists(file):
        print("path specified doesn't exist: %s" % (file))
        exit()


def check_unique(data, value):
    if value in data:
        return True
    else:
        return False


def check_exists(data, value):
    if value in data:
        return True
    else:
        return False


def check_exists_nested(matrix, value):
    flatten_matrix = [item for sublist in matrix for item in sublist]
    return check_exists(flatten_matrix, value)


def flatten_and_sort(matrix):
    flatten_matrix = [item for sublist in matrix for item in sublist]
    return flatten_matrix.sort()


def append_unique(data, value):
    data.append(value)


def check_entry_weight(data):
    if "-" in data:
        weight = 2
    else:
        weight = 1
    return weight


def percentage_decrease(a, b):
    '''Calculate the percentage amount decrease between 2 numbers.'''

    p = (((a - b)/a) * 100)
    return round(p, 2)


def check_list_space(data, entryWeightToAdd):
    serviceIndex = None

    for idx, val in enumerate(data):
        serviceEntryCount = 0  # reset counter for number of entries in this servicelist
        service = data[idx]

        # determine the entry count (serviceEntryCount) in the particular service list
        for entry in service:
            entryWeight = check_entry_weight(entry)
            serviceEntryCount = serviceEntryCount + entryWeight

            # If there is enough room in the service list to add the current entry to, then we set
            # the serviceIndex to be the index of this particular list. Otherwise it remains as
            # None, which means a new list will need to be created.
        if serviceEntryCount <= (15 - entryWeightToAdd):
            # spare capacity found in this list, so setting index of this list to return
            serviceIndex = idx

    return serviceIndex


def print_blank_line():
    print('\n')
