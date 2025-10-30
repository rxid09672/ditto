#!/usr/bin/env python3
"""Module for finding local nameserver

Retrieve the local nameserver from resolv.conf
Author: 0x636f646f
"""

import glob
import re


def check_for_resolv() -> list:
    """Check for the resolv.conf file"""
    resolv_conf_file = glob.glob('/etc/resolv.conf')
    if resolv_conf_file:
        return resolv_conf_file
    return []


def list_check(resolv_file) -> None:
    """Return exception if list empty"""
    if resolv_file:
        return
    if not resolv_file:
        raise ValueError('resolv.conf not found!')


def nameserver_regex_check(resolv_file) -> str:
    """return the nameserver ip"""
    pattern = re.compile(rb'^\w+\s(?P<nameserver>\d+\.\d+\.\d+\.\d+)$')
    nameserver = None

    if resolv_file:
        with open(resolv_file[0], 'rb') as r_file:
            for line in r_file.readlines():
                match = pattern.match(line)
                if match:
                    nameserver = match.group('nameserver').decode('utf-8')
                    break

    return nameserver


def return_nameserver_ip(nameserver_ip) -> str:
    """Print the nameserver if found"""
    if not nameserver_ip:
        raise ValueError("Nameserver not found!")
    return nameserver_ip


def main() -> None:
    """Execute the program"""
    resolv_file = check_for_resolv()
    list_check(resolv_file)
    nameserver_ip_search = nameserver_regex_check(resolv_file)
    nameserver_ip = return_nameserver_ip(nameserver_ip_search)
    print(nameserver_ip)


# Comment out the functions/variables and uncomment
# if __name__ == '__main__' block when using as a standalone script.


resolv_file = check_for_resolv()
list_check(resolv_file)
nameserver_ip_search = nameserver_regex_check(resolv_file)
nameserver_ip = return_nameserver_ip(nameserver_ip_search)
print(nameserver_ip)


# if __name__ == '__main__':
#    main()
