#! /usr/bin/env python3
##
# ZeroTier Network Controller
# By Amos <LFlare> Ng
##
from ipaddress import *
import argparse
import atexit
import json
import pickle
import platform
import requests
import sys
import collections

base_api = "http://127.0.0.1:9993"
ctrlr = None


def pprint(obj):
    print(json.dumps(obj, indent=2, separators=(',', ': ')))


def ddict():
    return collections.defaultdict(ddict)


def request(url, payload=None, method="get"):
    """Simple request wrapper

    Takes a couple of variables and wraps around the requests
    module

    Args:
        url: API URL
        method: Query method (default: {"get"})
        payload: JSON payload (default: {None})

    Returns:
        Dataset as result from query
        JSON Object
    """
    r = None
    if payload is not None:
        r = requests.post(
            base_api+url, headers=ctrlr["headers"], json=payload)
    elif method == "get":
        r = requests.get(
            base_api+url, headers=ctrlr["headers"])
    elif method == "delete":
        r = requests.delete(
            base_api+url, headers=ctrlr["headers"])
    return r.json()


def save_ctrlr():
    with open(get_filepath()+"/ctrlr.pickle", "wb") as file:
        pickle.dump(ctrlr, file)


def load_ctrlr():
    global ctrlr
    try:
        with open(get_filepath()+"/ctrlr.pickle", "rb") as file:
            ctrlr = pickle.load(file)
    except:
        ctrlr = ddict()


def get_filepath():
    """Get filepath according to OS"""
    if platform.system() == "Linux":
        return "/var/lib/zerotier-one"
    elif platform.system() == "Darwin":
        return "/Library/Application Support/ZeroTier/One"


def set_headers():
    """Sets authentication headers globally

    Automatically detect system and reads authtoken.secret
    to set authenticaiton headers used in request method
    globally.
    """
    with open(get_filepath()+"/authtoken.secret") as file:
        ctrlr["headers"] = {"X-ZT1-Auth": file.read()}


def set_id():
    ctrlr["ztid"] = request("/status").get("address")


def valid_nwid(nwid):
    return nwid is not None and (len(nwid) == 16 or len(nwid) == 6)


def valid_ztid(ztid):
    return ztid is not None and len(ztid) == 10


def alias(alias=None, nwid=None, ztid=None):
    if alias is not None:

        # Set alias
        if valid_nwid(nwid):

            # Set member alias
            if valid_ztid(ztid):
                pprint(ctrlr["network"][nwid]["member"])
                ctrlr["network"][nwid]["member"][ztid]["alias"] = alias
                return ctrlr["network"][nwid]["member"]

            # Set network alias
            else:
                ctrlr["network"][nwid]["alias"] = alias
                request("/controller/network/"+nwid, {"name": alias})
                return ctrlr["network"]

        # Get from alias
        else:

            # Get member from alias
            if ":" in alias:
                nwalias, ztalias = alias.split(":")
                for x, y in ctrlr["network"].items():
                    if nwalias == y["alias"]:
                        for xx, yy in ctrlr["network"][x]["member"].items():
                            if ztalias == yy["alias"]:
                                return x, xx

            # Get network from alias
            else:
                for x, y in ctrlr["network"].items():
                    if y["alias"] == alias:
                        return x
    else:

        # Get alias
        if valid_nwid(nwid):

            # Get member alias
            if valid_ztid(ztid):
                for x, y in ctrlr["network"].items():
                    if nwid == x:
                        for xx, yy in ctrlr["network"][x]["member"].items():
                            if ztid == xx:
                                return y["alias"]+":"+yy["alias"]

            # Get network alias
            else:
                for x, y in ctrlr["network"].items():
                    if nwid == x:
                        return y["alias"]


def net_add(nwid):
    return request("/controller/network/"+ctrlr["ztid"]+nwid, {})


def net_del(nwid):
    if nwid in ctrlr["network"]:
        del ctrlr["network"][nwid]
    return request("/controller/network/"+nwid, method="delete")


def net_info(nwid):
    ctrlr["network"][nwid].update(request("/controller/network/"+nwid))
    return ctrlr["network"][nwid]


def net_list():
    nwids = request("/controller/network")
    new_nwids = dict()
    for nwid in nwids:
        new_nwids[nwid] = alias(nwid=nwid)
    return new_nwids


def net_ipset(nwid, ip):
    ipaddrs = list(ip_network(ip).hosts())
    start, end = tuple([str(x) for x in ipaddrs[::len(ipaddrs)-1]])
    net = net_info(nwid)
    net["v4AssignMode"] = {"zt": "true"}
    net["routes"] = [{"target": ip, "via": "null"}]
    net["ipAssignmentPools"] = [{"ipRangeStart": start, "ipRangeEnd": end}]
    return request("/controller/network/"+nwid, net)


def member_auth(nwid, ztid):
    net = net_info(nwid)
    member = net["member"][ztid]
    member["authorized"] = "true"
    return request("/controller/network/"+nwid+"/member/"+ztid, member)


def member_deauth(nwid, ztid):
    net = net_info(nwid)
    member = net["member"][ztid]
    member["authorized"] = "false"
    return request("/controller/network/"+nwid+"/member/"+ztid, member)


def member_delete(nwid, ztid):
    member = member_info(nwid, ztid)
    del member
    return request(
        "/controller/network/"+nwid+"/member/"+ztid,
        method="delete"
    )


def member_info(nwid, ztid):
    net = net_info(nwid)
    member = net["member"][ztid]
    member.update(request("/controller/network/"+nwid+"/member/"+ztid))
    return member


def member_ipset(nwid, ztid, ip):
    member = member_info(nwid, ztid)
    member["ipAssignments"] = [ip]
    member = request("/controller/network/"+nwid+"/member/"+ztid, member)
    return member


def member_list(nwid):
    ztids = request("/controller/network/"+nwid+"/member")
    new_ztids = dict()
    for ztid in ztids:
        new_ztids[ztid] = alias(nwid=nwid, ztid=ztid)
    return new_ztids


def main():
    # Load/Create controller and set atexit argument
    load_ctrlr()
    atexit.register(save_ctrlr)

    # Populate current fields
    set_headers()
    set_id()

    # Used to detect runtime variables and configurations
    parser = argparse.ArgumentParser()
    actions = parser.add_mutually_exclusive_group()

    # Management actions
    actions.add_argument("--alias", metavar="[Alias]")

    # Network actions
    actions.add_argument("--net-add", action="store_true")
    actions.add_argument("--net-del", action="store_true")
    actions.add_argument("--net-info", action="store_true")
    actions.add_argument("--net-ipset", metavar="[IP Address]")
    actions.add_argument("--net-list", action="store_true")

    # Member actions
    actions.add_argument("--member-auth", action="store_true")
    actions.add_argument("--member-deauth", action="store_true")
    actions.add_argument("--member-delete", action="store_true")
    actions.add_argument("--member-info", action="store_true")
    actions.add_argument("--member-ipset", metavar="[IP Address]")
    actions.add_argument("--member-list", action="store_true")

    # Variables
    parser.add_argument("-n", metavar="[Network ID]", default="______")
    parser.add_argument("-z", metavar="[Member ID]")

    # Alias
    parser.add_argument("a", metavar="[Alias]", nargs="?")

    # Parse arguments
    args = parser.parse_args()

    # Check if alias given
    if args.a and ":" in args.a:
        args.n, args.z = alias(alias=args.a)
    elif args.a:
        args.n = alias(alias=args.a)

    # Execute actions
    if args.alias:
        out = alias(alias=args.alias, nwid=args.n, ztid=args.z)
    elif args.net_add:
        out = net_add(nwid=args.n)
    elif args.net_del:
        out = net_del(nwid=args.n)
    elif args.net_info:
        out = net_info(nwid=args.n)
    elif args.net_ipset:
        out = net_ipset(nwid=args.n, ip=args.net_ipset)
    elif args.net_list:
        out = net_list()
    elif args.member_auth:
        out = member_auth(nwid=args.n, ztid=args.z)
    elif args.member_deauth:
        out = member_deauth(nwid=args.n, ztid=args.z)
    elif args.member_delete:
        out = member_delete(nwid=args.n, ztid=args.z)
    elif args.member_info:
        out = member_info(nwid=args.n, ztid=args.z)
    elif args.member_ipset:
        out = member_ipset(nwid=args.n, ztid=args.z, ip=args.member_ipset)
    elif args.member_list:
        out = member_list(nwid=args.n)
    else:
        parser.print_help()
        sys.exit(1)

    # Print output
    pprint(out)

if __name__ == "__main__":
    main()
