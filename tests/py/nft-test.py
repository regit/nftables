#!/usr/bin/python
#
# (C) 2014 by Ana Rey Botello <anarey@gmail.com>
#
# Based on iptables-test.py:
# (C) 2012 by Pablo Neira Ayuso <pablo@netfilter.org>"
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# Thanks to the Outreach Program for Women (OPW) for sponsoring this test
# infrastructure.

import sys
import os
import subprocess
import argparse
import signal

NFT_BIN = os.getenv('NFT', "src/nft")
TESTS_PATH = os.path.dirname(os.path.abspath(__file__))
TESTS_DIRECTORY = ["any", "arp", "bridge", "inet", "ip", "ip6"]
LOGFILE = "/tmp/nftables-test.log"
log_file = None
table_list = []
chain_list = []
all_set = dict()
obj_list = []
signal_received = 0


class Colors:
    if sys.stdout.isatty():
        HEADER = '\033[95m'
        GREEN = '\033[92m'
        YELLOW = '\033[93m'
        RED = '\033[91m'
        ENDC = '\033[0m'
    else:
        HEADER = ''
        GREEN = ''
        YELLOW = ''
        RED = ''
        ENDC = ''


class Chain:
    """Class that represents a chain"""

    def __init__(self, name, config, lineno):
        self.name = name
        self.config = config
        self.lineno = lineno

    def __eq__(self, other):
        return self.__dict__ == other.__dict__


class Table:
    """Class that represents a table"""

    def __init__(self, family, name, chains):
        self.family = family
        self.name = name
        self.chains = chains

    def __eq__(self, other):
        return self.__dict__ == other.__dict__


class Set:
    """Class that represents a set"""

    def __init__(self, family, table, name, type, flags):
        self.family = family
        self.table = table
        self.name = name
        self.type = type
        self.flags = flags

    def __eq__(self, other):
        return self.__dict__ == other.__dict__


class Obj:
    """Class that represents an object"""

    def __init__(self, table, family, name, type, spcf):
        self.table = table
        self.family = family
        self.name = name
        self.type = type
        self.spcf = spcf

    def __eq__(self, other):
        return self.__dict__ == other.__dict__


def print_msg(reason, filename=None, lineno=None, color=None, errstr=None):
    '''
    Prints a message with nice colors, indicating file and line number.
    '''
    if filename and lineno:
        print filename + ": " + color + "ERROR:" + Colors.ENDC + \
              " line %d: %s" % (lineno + 1, reason)
    else:
        print color + "ERROR:" + Colors.ENDC + " %s" % reason


def print_error(reason, filename=None, lineno=None):
    print_msg(reason, filename, lineno, Colors.RED, "ERROR:")


def print_warning(reason, filename=None, lineno=None):
    print_msg(reason, filename, lineno, Colors.YELLOW, "WARNING:")


def print_differences_warning(filename, lineno, rule1, rule2, cmd):
    reason = "'" + rule1 + "' mismatches '" + rule2 + "'"
    print filename + ": " + Colors.YELLOW + "WARNING: " + Colors.ENDC + \
          "line: " + str(lineno + 1) + ": '" + cmd + "': " + reason


def print_differences_error(filename, lineno, cmd):
    reason = "Listing is broken."
    print filename + ": " + Colors.RED + "ERROR: " + Colors.ENDC + "line: " + \
          str(lineno + 1) + ": '" + cmd + "': " + reason


def table_exist(table, filename, lineno):
    '''
    Exists a table.
    '''
    cmd = NFT_BIN + " list -nnn table " + table.family + " " + table.name
    ret = execute_cmd(cmd, filename, lineno)

    return True if (ret == 0) else False


def table_flush(table, filename, lineno):
    '''
    Flush a table.
    '''
    cmd = NFT_BIN + " flush table " + table.family + " " + table.name
    execute_cmd(cmd, filename, lineno)

    return cmd


def table_create(table, filename, lineno):
    '''
    Adds a table.
    '''
    # We check if table exists.
    if table_exist(table, filename, lineno):
        reason = "Table " + table.name + " already exists"
        print_error(reason, filename, lineno)
        return -1

    table_list.append(table)

    # We add a new table
    cmd = NFT_BIN + " add table " + table.family + " " + table.name
    ret = execute_cmd(cmd, filename, lineno)

    if ret != 0:
        reason = "Cannot add table " + table.name
        print_error(reason, filename, lineno)
        table_list.remove(table)
        return -1

    # We check if table was added correctly.
    if not table_exist(table, filename, lineno):
        table_list.remove(table)
        reason = "I have just added the table " + table.name + \
                 " but it does not exist. Giving up!"
        print_error(reason, filename, lineno)
        return -1

    for table_chain in table.chains:
        chain = chain_get_by_name(table_chain)
        if chain is None:
            reason = "The chain " + table_chain + " requested by table " + \
                     table.name + " does not exist."
            print_error(reason, filename, lineno)
        else:
            chain_create(chain, table, filename)

    return 0


def table_delete(table, filename=None, lineno=None):
    '''
    Deletes a table.
    '''
    table_info = " " + table.family + " " + table.name + " "

    if not table_exist(table, filename, lineno):
        reason = "Table " + table.name + \
                 " does not exist but I added it before."
        print_error(reason, filename, lineno)
        return -1

    cmd = NFT_BIN + " delete table" + table_info
    ret = execute_cmd(cmd, filename, lineno)
    if ret != 0:
        reason = cmd + ": " + "I cannot delete table '" + table.name + \
                 "'. Giving up! "
        print_error(reason, filename, lineno)
        return -1

    if table_exist(table, filename, lineno):
        reason = "I have just deleted the table " + table.name + \
                 " but the table still exists."
        print_error(reason, filename, lineno)
        return -1

    return 0


def chain_exist(chain, table, filename):
    '''
    Checks a chain
    '''
    table_info = " " + table.family + " " + table.name + " "
    cmd = NFT_BIN + " list -nnn chain" + table_info + chain.name
    ret = execute_cmd(cmd, filename, chain.lineno)

    return True if (ret == 0) else False


def chain_create(chain, table, filename):
    '''
    Adds a chain
    '''
    table_info = " " + table.family + " " + table.name + " "

    if chain_exist(chain, table, filename):
        reason = "This chain '" + chain.name + "' exists in " + table.name + \
                 ". I cannot create two chains with same name."
        print_error(reason, filename, chain.lineno)
        return -1

    cmd = NFT_BIN + " add chain" + table_info + chain.name + \
          "\{ " + chain.config + "\; \}"

    ret = execute_cmd(cmd, filename, chain.lineno)
    if ret != 0:
        reason = "I cannot create the chain '" + chain.name
        print_error(reason, filename, chain.lineno)
        return -1

    if not chain_exist(chain, table, filename):
        reason = "I have added the chain '" + chain.name + \
                 "' but it does not exist in " + table.name
        print_error(reason, filename, chain.lineno)
        return -1

    return 0


def chain_delete(chain, table, filename=None, lineno=None):
    '''
    Flushes and deletes a chain.
    '''
    table_info = " " + table.family + " " + table.name + " "

    if not chain_exist(chain, table, filename):
        reason = "The chain " + chain.name + " does not exists in " + \
                 table.name + ". I cannot delete it."
        print_error(reason, filename, lineno)
        return -1

    cmd = NFT_BIN + " flush chain" + table_info + chain.name
    ret = execute_cmd(cmd, filename, lineno)
    if ret != 0:
        reason = "I cannot flush this chain " + chain.name
        print_error(reason, filename, lineno)
        return -1

    cmd = NFT_BIN + " delete chain" + table_info + chain.name
    ret = execute_cmd(cmd, filename, lineno)
    if ret != 0:
        reason = cmd + "I cannot delete this chain. DD"
        print_error(reason, filename, lineno)
        return -1

    if chain_exist(chain, table, filename):
        reason = "The chain " + chain.name + " exists in " + table.name + \
                 ". I cannot delete this chain"
        print_error(reason, filename, lineno)
        return -1

    return 0


def chain_get_by_name(name):
    for chain in chain_list:
        if chain.name == name:
            break
    else:
        chain = None

    return chain


def set_add(s, test_result, filename, lineno):
    '''
    Adds a set.
    '''
    if not table_list:
        reason = "Missing table to add rule"
        print_error(reason, filename, lineno)
        return -1

    for table in table_list:
        s.table = table.name
        s.family = table.family
        if _set_exist(s, filename, lineno):
            reason = "Set " + s.name + " already exists in " + table.name
            print_error(reason, filename, lineno)
            return -1

        table_handle = " " + table.family + " " + table.name + " "
        if s.flags == "":
            set_cmd = " " + s.name + " { type " + s.type + "\;}"
        else:
            set_cmd = " " + s.name + " { type " + s.type + "\; flags " + s.flags + "\; }"

        cmd = NFT_BIN + " add set" + table_handle + set_cmd
        ret = execute_cmd(cmd, filename, lineno)

        if (ret == 0 and test_result == "fail") or \
                (ret != 0 and test_result == "ok"):
            reason = cmd + ": " + "I cannot add the set " + s.name
            print_error(reason, filename, lineno)
            return -1

        if not _set_exist(s, filename, lineno):
            reason = "I have just added the set " + s.name + \
                     " to the table " + table.name + " but it does not exist"
            print_error(reason, filename, lineno)
            return -1

    return 0


def set_add_elements(set_element, set_name, state, filename, lineno):
    '''
    Adds elements to the set.
    '''
    if not table_list:
        reason = "Missing table to add rules"
        print_error(reason, filename, lineno)
        return -1

    for table in table_list:
        # Check if set exists.
        if (not set_exist(set_name, table, filename, lineno) or
                    set_name not in all_set) and state == "ok":
            reason = "I cannot add an element to the set " + set_name + \
                     " since it does not exist."
            print_error(reason, filename, lineno)
            return -1

        table_info = " " + table.family + " " + table.name + " "

        element = ""
        for e in set_element:
            if not element:
                element = e
            else:
                element = element + ", " + e

        set_text = set_name + " { " + element + " }"
        cmd = NFT_BIN + " add element" + table_info + set_text
        ret = execute_cmd(cmd, filename, lineno)

        if (state == "fail" and ret == 0) or (state == "ok" and ret != 0):
            test_state = "This rule should have failed."
            reason = cmd + ": " + test_state
            print_error(reason, filename, lineno)
            return -1

        # Add element into a all_set.
        if ret == 0 and state == "ok":
            for e in set_element:
                all_set[set_name].add(e)

    return 0


def set_delete_elements(set_element, set_name, table, filename=None,
                        lineno=None):
    '''
    Deletes elements in a set.
    '''
    table_info = " " + table.family + " " + table.name + " "

    for element in set_element:
        set_text = set_name + " {" + element + "}"
        cmd = NFT_BIN + " delete element" + table_info + set_text
        ret = execute_cmd(cmd, filename, lineno)
        if ret != 0:
            reason = "I cannot delete an element" + element + \
                     " from the set '" + set_name
            print_error(reason, filename, lineno)
            return -1

    return 0


def set_delete(table, filename=None, lineno=None):
    '''
    Deletes set and its content.
    '''
    for set_name in all_set.keys():
        # Check if exists the set
        if not set_exist(set_name, table, filename, lineno):
            reason = "The set " + set_name + \
                     " does not exist, I cannot delete it"
            print_error(reason, filename, lineno)
            return -1

        # We delete all elements in the set
        set_delete_elements(all_set[set_name], set_name, table, filename,
                            lineno)

        # We delete the set.
        table_info = " " + table.family + " " + table.name + " "
        cmd = NFT_BIN + " delete set " + table_info + " " + set_name
        ret = execute_cmd(cmd, filename, lineno)

        # Check if the set still exists after I deleted it.
        if ret != 0 or set_exist(set_name, table, filename, lineno):
            reason = "Cannot remove the set " + set_name
            print_error(reason, filename, lineno)
            return -1

    return 0


def set_exist(set_name, table, filename, lineno):
    '''
    Check if the set exists.
    '''
    table_info = " " + table.family + " " + table.name + " "
    cmd = NFT_BIN + " list -nnn set" + table_info + set_name
    ret = execute_cmd(cmd, filename, lineno)

    return True if (ret == 0) else False


def _set_exist(s, filename, lineno):
    '''
    Check if the set exists.
    '''
    table_handle = " " + s.family + " " + s.table + " "
    cmd = NFT_BIN + " list -nnn set" + table_handle + s.name
    ret = execute_cmd(cmd, filename, lineno)

    return True if (ret == 0) else False


def set_check_element(rule1, rule2):
    '''
    Check if element exists in anonymous sets.
    '''
    ret = -1
    pos1 = rule1.find("{")
    pos2 = rule2.find("{")
    end1 = rule1.find("}")
    end2 = rule2.find("}")

    if (pos1 != -1) and (pos2 != -1) and (end1 != -1) and (end2 != -1):
        list1 = (rule1[pos1 + 1:end1].replace(" ", "")).split(",")
        list2 = (rule2[pos2 + 1:end2].replace(" ", "")).split(",")
        list1.sort()
        list2.sort()
        if cmp(list1, list2) == 0:
            ret = 0

    if ret != 0:
        return ret

    return cmp(rule1[end1:], rule2[end2:])


def obj_add(o, test_result, filename, lineno):
    '''
    Adds an object.
    '''
    if not table_list:
        reason = "Missing table to add rule"
        print_error(reason, filename, lineno)
        return -1

    for table in table_list:
        o.table = table.name
        o.family = table.family
        obj_handle = o.type + " " + o.name
        if _obj_exist(o, filename, lineno):
            reason = "The " + obj_handle + " already exists in " + table.name
            print_error(reason, filename, lineno)
            return -1

        table_handle = " " + table.family + " " + table.name + " "

        cmd = NFT_BIN + " add " + o.type + table_handle + o.name + " " + o.spcf
        ret = execute_cmd(cmd, filename, lineno)

        if (ret == 0 and test_result == "fail") or \
                (ret != 0 and test_result == "ok"):
            reason = cmd + ": " + "I cannot add the " + obj_handle
            print_error(reason, filename, lineno)
            return -1

        exist = _obj_exist(o, filename, lineno)

        if exist:
            if test_result == "ok":
                 return 0
            reason = "I added the " + obj_handle + \
                     " to the table " + table.name + " but it should have failed"
            print_error(reason, filename, lineno)
            return -1

        if test_result == "fail":
            return 0

        reason = "I have just added the " + obj_handle + \
                 " to the table " + table.name + " but it does not exist"
        print_error(reason, filename, lineno)
        return -1

def obj_delete(table, filename=None, lineno=None):
    '''
    Deletes object.
    '''
    for o in obj_list:
        obj_handle = o.type + " " + o.name
        # Check if exists the obj
        if not obj_exist(o, table, filename, lineno):
            reason = "The " + obj_handle + " does not exist, I cannot delete it"
            print_error(reason, filename, lineno)
            return -1

        # We delete the object.
        table_info = " " + table.family + " " + table.name + " "
        cmd = NFT_BIN + " delete " + o.type + table_info + " " + o.name
        ret = execute_cmd(cmd, filename, lineno)

        # Check if the object still exists after I deleted it.
        if ret != 0 or obj_exist(o, table, filename, lineno):
            reason = "Cannot remove the " + obj_handle
            print_error(reason, filename, lineno)
            return -1

    return 0


def obj_exist(o, table, filename, lineno):
    '''
    Check if the object exists.
    '''
    table_handle = " " + table.family + " " + table.name + " "
    cmd = NFT_BIN + " list -nnn " + o.type + table_handle + o.name
    ret = execute_cmd(cmd, filename, lineno)

    return True if (ret == 0) else False


def _obj_exist(o, filename, lineno):
    '''
    Check if the object exists.
    '''
    table_handle = " " + o.family + " " + o.table + " "
    cmd = NFT_BIN + " list -nnn " + o.type + table_handle + o.name
    ret = execute_cmd(cmd, filename, lineno)

    return True if (ret == 0) else False


def output_clean(pre_output, chain):
    pos_chain = pre_output.find(chain.name)
    if pos_chain == -1:
        return ""
    output_intermediate = pre_output[pos_chain:]
    brace_start = output_intermediate.find("{")
    brace_end = output_intermediate.find("}")
    pre_rule = output_intermediate[brace_start:brace_end]
    if pre_rule[1:].find("{") > -1:  # this rule has a set.
        set = pre_rule[1:].replace("\t", "").replace("\n", "").strip()
        set = set.split(";")[2].strip() + "}"
        remainder = output_clean(chain.name + " {;;" + output_intermediate[brace_end+1:], chain)
        if len(remainder) <= 0:
            return set
        return set + " " + remainder
    else:
        rule = pre_rule.split(";")[2].replace("\t", "").replace("\n", "").\
            strip()
    if len(rule) < 0:
        return ""
    return rule


def payload_check_elems_to_set(elems):
    newset = set()

    for n, line in enumerate(elems.split('[end]')):
        e = line.strip()
        if e in newset:
            print_error("duplicate", e, n)
            return newset

        newset.add(e)

    return newset


def payload_check_set_elems(want, got):
    if want.find('element') < 0 or want.find('[end]') < 0:
        return 0

    if got.find('element') < 0 or got.find('[end]') < 0:
        return 0

    set_want = payload_check_elems_to_set(want)
    set_got = payload_check_elems_to_set(got)

    return set_want == set_got


def payload_check(payload_buffer, file, cmd):
    file.seek(0, 0)
    i = 0

    for lineno, want_line in enumerate(payload_buffer):
        line = file.readline()

        if want_line == line:
            i += 1
            continue

        if want_line.find('[') < 0 and line.find('[') < 0:
            continue
        if want_line.find(']') < 0 and line.find(']') < 0:
            continue

        if payload_check_set_elems(want_line, line):
            continue

        print_differences_warning(file.name, lineno, want_line.strip(),
                                  line.strip(), cmd)
        return 0

    return i > 0


def rule_add(rule, filename, lineno, force_all_family_option, filename_path):
    '''
    Adds a rule
    '''
    # TODO Check if a rule is added correctly.
    ret = warning = error = unit_tests = 0

    if not table_list or not chain_list:
        reason = "Missing table or chain to add rule."
        print_error(reason, filename, lineno)
        return [-1, warning, error, unit_tests]

    payload_expected = []

    for table in table_list:
        try:
            payload_log = open("%s.payload.%s" % (filename_path, table.family))
        except IOError:
            payload_log = open("%s.payload" % filename_path)

        if rule[1].strip() == "ok":
            try:
                payload_expected.index(rule[0])
            except ValueError:
                payload_expected = payload_find_expected(payload_log, rule[0])

                if not payload_expected:
                    print_error("did not find payload information for "
                                "rule '%s'" % rule[0], payload_log.name, 1)

        for table_chain in table.chains:
            chain = chain_get_by_name(table_chain)
            unit_tests += 1
            table_flush(table, filename, lineno)
            table_info = " " + table.family + " " + table.name + " "

            payload_log = os.tmpfile()

            cmd = NFT_BIN + " add rule --debug=netlink" + table_info + \
                  chain.name + " " + rule[0]
            ret = execute_cmd(cmd, filename, lineno, payload_log)

            state = rule[1].rstrip()
            if (ret == 0 and state == "fail") or (ret != 0 and state == "ok"):
                if state == "fail":
                    test_state = "This rule should have failed."
                else:
                    test_state = "This rule should not have failed."
                reason = cmd + ": " + test_state
                print_error(reason, filename, lineno)
                ret = -1
                error += 1
                if not force_all_family_option:
                    return [ret, warning, error, unit_tests]

            if state == "fail" and ret != 0:
                ret = 0
                continue

            if ret == 0:
                # Check for matching payload
                if state == "ok" and not payload_check(payload_expected,
                                                       payload_log, cmd):
                    error += 1
                    gotf = open("%s.payload.got" % filename_path, 'a')
                    payload_log.seek(0, 0)
                    gotf.write("# %s\n" % rule[0])
                    while True:
                        line = payload_log.readline()
                        if line == "":
                            break
                        gotf.write(line)
                    gotf.close()
                    print_warning("Wrote payload for rule %s" % rule[0],
                                  gotf.name, 1)

                # Check output of nft
                process = subprocess.Popen([NFT_BIN, '-nnns', 'list', 'table',
                                            table.family, table.name],
                                           shell=False,
                                           stdout=subprocess.PIPE,
                                           preexec_fn=preexec)
                pre_output = process.communicate()
                output = pre_output[0].split(";")
                if len(output) < 2:
                    reason = cmd + ": Listing is broken."
                    print_error(reason, filename, lineno)
                    ret = -1
                    error += 1
                    if not force_all_family_option:
                        return [ret, warning, error, unit_tests]
                else:
                    rule_output = output_clean(pre_output[0], chain)
                    if len(rule) == 3:
                        teoric_exit = rule[2]
                    else:
                        teoric_exit = rule[0]

                    if rule_output.rstrip() != teoric_exit.rstrip():
                        if rule[0].find("{") != -1:  # anonymous sets
                            if set_check_element(teoric_exit.rstrip(), rule_output.rstrip()) != 0:
                                warning += 1
                                print_differences_warning(filename, lineno,
                                                          rule[0], rule_output,
                                                          cmd)
                                if not force_all_family_option:
                                    return [ret, warning, error, unit_tests]
                        else:
                            if len(rule_output) <= 0:
                                error += 1
                                print_differences_error(filename, lineno, cmd)
                                if not force_all_family_option:
                                    return [ret, warning, error, unit_tests]

                            warning += 1
                            print_differences_warning(filename, lineno,
                                                      teoric_exit.rstrip(),
                                                      rule_output, cmd)

                            if not force_all_family_option:
                                return [ret, warning, error, unit_tests]

    return [ret, warning, error, unit_tests]


def preexec():
    os.setpgrp()  # Don't forward signals.


def cleanup_on_exit():
    for table in table_list:
        for table_chain in table.chains:
            chain = chain_get_by_name(table_chain)
            chain_delete(chain, table, "", "")
        if all_set:
            set_delete(table)
        if obj_list:
            obj_delete(table)
        table_delete(table)


def signal_handler(signal, frame):
    global signal_received
    signal_received = 1


def execute_cmd(cmd, filename, lineno, stdout_log=False):
    '''
    Executes a command, checks for segfaults and returns the command exit
    code.

    :param cmd: string with the command to be executed
    :param filename: name of the file tested (used for print_error purposes)
    :param lineno: line number being tested (used for print_error purposes)
    '''
    global log_file
    print >> log_file, "command: %s" % cmd
    if debug_option:
        print cmd

    if not stdout_log:
        stdout_log = log_file

    ret = subprocess.call(cmd, shell=True, universal_newlines=True,
                          stderr=log_file, stdout=stdout_log,
                          preexec_fn=preexec)
    log_file.flush()

    if ret == -11:
        reason = "command segfaults: " + cmd
        print_error(reason, filename, lineno)

    return ret


def print_result(filename, tests, warning, error):
    return str(filename) + ": " + str(tests) + " unit tests, " + str(error) + \
           " error, " + str(warning) + " warning"


def print_result_all(filename, tests, warning, error, unit_tests):
    return str(filename) + ": " + str(tests) + " unit tests, " + \
           str(unit_tests) + " total test executed, " + str(error) + \
           " error, " + str(warning) + " warning"


def table_process(table_line, filename, lineno):
    table_info = table_line.split(";")
    table = Table(table_info[0], table_info[1], table_info[2].split(","))

    return table_create(table, filename, lineno)


def chain_process(chain_line, lineno):
    chain_info = chain_line.split(";")
    chain_list.append(Chain(chain_info[0], chain_info[1], lineno))

    return 0


def set_process(set_line, filename, lineno):
    test_result = set_line[1]

    tokens = set_line[0].split(" ")
    set_name = tokens[0]
    set_type = tokens[2]

    if len(tokens) == 5 and tokens[3] == "flags":
        set_flags = tokens[4]
    else:
        set_flags = ""

    s = Set("", "", set_name, set_type, set_flags)

    ret = set_add(s, test_result, filename, lineno)
    if ret == 0:
        all_set[set_name] = set()

    return ret


def set_element_process(element_line, filename, lineno):
    rule_state = element_line[1]
    set_name = element_line[0].split(" ")[0]
    set_element = element_line[0].split(" ")
    set_element.remove(set_name)
    return set_add_elements(set_element, set_name, rule_state, filename, lineno)


def obj_process(obj_line, filename, lineno):
    test_result = obj_line[1]

    tokens = obj_line[0].split(" ")
    obj_name = tokens[0]
    obj_type = tokens[2]
    obj_spcf = ""

    if obj_type == "ct" and tokens[3] == "helper":
       obj_type = "ct helper"
       tokens[3] = ""

    if len(tokens) > 3:
        obj_spcf = " ".join(tokens[3:])

    o = Obj("", "", obj_name, obj_type, obj_spcf)

    ret = obj_add(o, test_result, filename, lineno)
    if ret == 0:
        obj_list.append(o)

    return ret


def payload_find_expected(payload_log, rule):
    '''
    Find the netlink payload that should be generated by given rule in
    payload_log

    :param payload_log: open file handle of the payload data
    :param rule: nft rule we are going to add
    '''
    found = 0
    payload_buffer = []

    while True:
        line = payload_log.readline()
        if not line:
            break

        if line[0] == "#":  # rule start
            rule_line = line.strip()[2:]

            if rule_line == rule.strip():
                found = 1
                continue

        if found == 1:
            payload_buffer.append(line)
            if line.isspace():
                return payload_buffer

    payload_log.seek(0, 0)
    return payload_buffer


def run_test_file(filename, force_all_family_option, specific_file):
    '''
    Runs a test file

    :param filename: name of the file with the test rules
    '''
    filename_path = os.path.join(TESTS_PATH, filename)
    f = open(filename_path)
    tests = passed = total_unit_run = total_warning = total_error = 0

    for lineno, line in enumerate(f):
        sys.stdout.flush()

        if signal_received == 1:
            print "\nSignal received. Cleaning up and Exitting..."
            cleanup_on_exit()
            sys.exit(0)

        if line.isspace():
            continue

        if line[0] == "#":  # Command-line
            continue

        if line[0] == '*':  # Table
            table_line = line.rstrip()[1:]
            ret = table_process(table_line, filename, lineno)
            if ret != 0:
                break
            continue

        if line[0] == ":":  # Chain
            chain_line = line.rstrip()[1:]
            ret = chain_process(chain_line, lineno)
            if ret != 0:
                break
            continue

        if line[0] == "!":  # Adds this set
            set_line = line.rstrip()[1:].split(";")
            ret = set_process(set_line, filename, lineno)
            tests += 1
            if ret == -1:
                continue
            passed += 1
            continue

        if line[0] == "?":  # Adds elements in a set
            element_line = line.rstrip()[1:].split(";")
            ret = set_element_process(element_line, filename, lineno)
            tests += 1
            if ret == -1:
                continue

            passed += 1
            continue

        if line[0] == "%":  # Adds this object
            brace = line.rfind("}")
            if brace < 0:
                obj_line = line.rstrip()[1:].split(";")
            else:
                obj_line = (line[1:brace+1], line[brace+2:].rstrip())

            ret = obj_process(obj_line, filename, lineno)
            tests += 1
            if ret == -1:
                continue
            passed += 1
            continue

        # Rule
        rule = line.split(';')  # rule[1] Ok or FAIL
        if len(rule) == 1 or len(rule) > 3 or rule[1].rstrip() \
                not in {"ok", "fail"}:
            reason = "Skipping malformed rule test. (" + line.rstrip('\n') + ")"
            print_warning(reason, filename, lineno)
            continue

        if line[0] == "-":  # Run omitted lines
            if need_fix_option:
                rule[0] = rule[0].rstrip()[1:].strip()
            else:
                continue
        elif need_fix_option:
            continue

        result = rule_add(rule, filename, lineno, force_all_family_option,
                          filename_path)
        tests += 1
        ret = result[0]
        warning = result[1]
        total_warning += warning
        total_error += result[2]
        total_unit_run += result[3]

        if ret != 0:
            continue

        if warning == 0:  # All ok.
            passed += 1

    # Delete rules, sets, chains and tables
    for table in table_list:
        # We delete chains
        for table_chain in table.chains:
            chain = chain_get_by_name(table_chain)
            chain_delete(chain, table, filename, lineno)

        # We delete sets.
        if all_set:
            ret = set_delete(table, filename, lineno)
            if ret != 0:
                reason = "There is a problem when we delete a set"
                print_error(reason, filename, lineno)

        # We delete tables.
        table_delete(table, filename, lineno)

    if specific_file:
        if force_all_family_option:
            print print_result_all(filename, tests, total_warning, total_error,
                                   total_unit_run)
        else:
            print print_result(filename, tests, total_warning, total_error)
    else:
        if tests == passed and tests > 0:
            print filename + ": " + Colors.GREEN + "OK" + Colors.ENDC

    f.close()
    del table_list[:]
    del chain_list[:]
    all_set.clear()

    return [tests, passed, total_warning, total_error, total_unit_run]


def main():
    parser = argparse.ArgumentParser(description='Run nft tests', version='1.0')

    parser.add_argument('filename', nargs='?', metavar='path/to/file.t',
                        help='Run only this test')

    parser.add_argument('-d', '--debug', action='store_true', dest='debug',
                        help='enable debugging mode')

    parser.add_argument('-e', '--need-fix', action='store_true',
                        dest='need_fix_line', help='run rules that need a fix')

    parser.add_argument('-f', '--force-family', action='store_true',
                        dest='force_all_family',
                        help='keep testing all families on error')

    args = parser.parse_args()
    global debug_option, need_fix_option
    debug_option = args.debug
    need_fix_option = args.need_fix_line
    force_all_family_option = args.force_all_family
    specific_file = False

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    if os.getuid() != 0:
        print "You need to be root to run this, sorry"
        return

    # Change working directory to repository root
    os.chdir(TESTS_PATH + "/../..")

    if not os.path.isfile(NFT_BIN):
        print "The nft binary does not exist. You need to build the project."
        return

    test_files = files_ok = run_total = 0
    tests = passed = warnings = errors = 0
    global log_file
    try:
        log_file = open(LOGFILE, 'w')
    except IOError:
        print "Cannot open log file %s" % LOGFILE
        return

    file_list = []
    if args.filename:
        file_list = [args.filename]
        specific_file = True
    else:
        for directory in TESTS_DIRECTORY:
            path = os.path.join(TESTS_PATH, directory)
            for root, dirs, files in os.walk(path):
                for f in files:
                    if f.endswith(".t"):
                        file_list.append(os.path.join(directory, f))

    for filename in file_list:
        result = run_test_file(filename, force_all_family_option, specific_file)
        file_tests = result[0]
        file_passed = result[1]
        file_warnings = result[2]
        file_errors = result[3]
        file_unit_run = result[4]

        test_files += 1

        if file_warnings == 0 and file_tests == file_passed:
            files_ok += 1
        if file_tests:
            tests += file_tests
            passed += file_passed
            errors += file_errors
            warnings += file_warnings
        if force_all_family_option:
            run_total += file_unit_run

    if test_files == 0:
        print "No test files to run"
    else:
        if not specific_file:
            if force_all_family_option:
                print "%d test files, %d files passed, %d unit tests, " \
                      "%d total executed, %d error, %d warning" \
                      % (test_files, files_ok, tests, run_total, errors,
                         warnings)
            else:
                print "%d test files, %d files passed, %d unit tests, " \
                      "%d error, %d warning" \
                      % (test_files, files_ok, tests, errors, warnings)


if __name__ == '__main__':
    main()
