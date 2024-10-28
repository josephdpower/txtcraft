''' This script formats domains and IP addresses for an RPZ and IDP
You can only do one function at a time (probably) '''
#!/usr/bin/python3

import argparse
import datetime
import re
import sys

## setup argparse
parser = argparse.ArgumentParser()

parser.add_argument("-rb", "--rpzblacklist", action='store', \
help="Format the list of domains you provide here for the RPZ blacklist")

parser.add_argument("-rw","--rpzwhitelist", action='store', \
                    help="Format a file of domains for the RPZ whitelist")

parser.add_argument("-ib", "--ipblacklist", action='store',  \
                    help="Format a file of IPs for the IDP blacklist, format [127.0.0.1 #Comment]")

parser.add_argument("-iw", "--ipwhitelist", action='store',
                     help="Formats a file of IPs for the IDP whitelist \
                     and defang if required. Format: 127.0.0.1")

args = parser.parse_args()

# output file names

rpzwhitelist_txt = f"RPZ_WL-{datetime.date.today()}.txt"
rpzblacklist_txt = f'RPZ_BL-{datetime.date.today()}.txt'
ipblacklist_txt = f"IP_BL-{datetime.date.today()}.txt"
ipwhitelist_txt = f"IP_WL-{datetime.date.today()}.txt"

# setup functions

'''
TODO: Ideally, refactor the defang parts of these functions into its own function
Example usage within argparse: defangalang(blacklist_IPs(IPs)) ?
maybe also un-break the function so it works with a URL like
hxxps[://]google[.]com '''

def blacklist_ips(input_file: str) -> None:
    '''Convert list of IOCs (IPs) from a file and output into new file. 
    Will also defang them
    
    :param input_file: file specified by absolute or relative file path
    :raises FileNotFoundError: If the input file does not exist
    '''

    try:
        # read input file
        with open(input_file, 'r', encoding="utf-8") as f:
            contents = f.readlines()

        with open(f"{ipblacklist_txt}", 'w', encoding="utf-8") as f_out:
        # add user comment before the loop, defang input, write to output file
            comment = input("Insert job comment \\n \
                Comment: #")
            for lines in contents:
                ip_addresses = lines.strip().replace("[","").replace("]","")
                f_out.write(f"{ip_addresses} #{comment}\n")

    except FileNotFoundError:
        sys.exit("You done goofed: file does not exist")

def whitelist_ips(input_ips: str) -> None:
    '''Convert list of IOCs (IP addresses) to a formatted .txt file
    Will defang if required. Will also have no comment due to current
    IDP Bash script that would render it broke as hell '''
    try:
        with open(input_ips, 'r', encoding="utf-8") as f:
            contents = f.readlines()

        with open(f"{ipwhitelist_txt}", 'w', encoding="utf-8") as f_out:
            # write output file, ensuring no whitespace or comments
            for lines in contents:
                ip_addresses = contents
                ip_addresses = lines.strip().replace("[","").replace("]","")
                f_out.write(f"{ip_addresses}\n")

    except FileNotFoundError:
        sys.exit("You done goofed: file does not exist")

def domains_rpz_blacklist(domains: str) -> None:
    '''Convert list of URLs in a file to RPZ blacklist format
    Will defang if required.


    Example output:
    baddomain.com   TXT "Class: Malicious as hell, REQexample123, powerj, 23052024"
    baddomainl.com  A   127.66.66.66

    :param input_file: File specified by absolute or relative file path
    :raises FileNotFoundError: if input file doesn't exist
    '''
    try:
        # read input file
        with open(domains, 'r', encoding="utf-8") as f:
            contents = [line.strip() for line in f]

        with open(f"{rpzblacklist_txt}", 'w', encoding="utf-8") as f_out:
        # add user comment before the loop, defang input, write to output file
            print("Enter TXT record (e.g. 'TXT: Class: Phishing, powerj, 01012020)")
            txt_record = input("'TXT: '")

            a_record = "A 127.66.66.66"

            for lines in contents:
                contents = lines.strip().replace("hxxps[://]","").replace("hxxp[://]","")
                contents = lines.replace("[","").replace("]","")
                pattern = "https?://"
                pattern_2 = "hxxps?://"
                contents = re.sub(pattern, "", contents)
                contents = re.sub(pattern_2, "", contents)
                contents = re.sub(r'^www\.', '*.', contents)
                domain = contents
                f_out.writelines(f"{domain}     TXT \"{txt_record}\"\n{domain}    {a_record}\n")

    except FileNotFoundError:
        sys.exit("You done goofed. File does not exist")

def domains_rpz_whitelist(domains: str) -> None:
    '''Read a file of domains, defang them, add comment, and format for RPZ whitelist

    Example output:
    ; powerj, REQexample123, 23052024
    gooddomain.com  CNAME   rpz-passthru.

    :param input_file: Specified by absolute or relative path
    :raises FileNotFoundError: if input file doesn't exist
    '''
    try:
        with open(domains, 'r', encoding="utf-8") as f:
            contents = [line.strip() for line in f]

        with open(f"{rpzwhitelist_txt}", 'w', encoding="utf-8") as f_out:
            print("Enter comment -- Format: \"; powerj, REQ1234, 01012020")
            comment = input("Comment : ;")

            comment = f";{comment}"
            for lines in contents:
                contents = lines.strip().replace("hxxps[://]","").replace("hxxp[://]","")
                contents = lines.replace("[","").replace("]","")
                pattern = "https?://|hxxps?://"
                contents = re.sub(pattern, "", contents)
                contents = re.sub(r'^www\.', '*.', contents)
                domain = contents
                f_out.writelines(f"{comment}\n{domain}  CNAME   rpz-passthru.\n")

    except FileNotFoundError:
        sys.exit("You done goofed: file does not exist")

if __name__ == "__main__":
    print(r'''
_______   _______     .___________.___   ___ .___________.  ______ .______          ___       _______ .___________.
|       \ |       \    |           |\  \ /  / |           | /      ||   _  \        /   \     |   ____||           |
|  .--.  ||  .--.  |   `---|  |----` \  V  /  `---|  |----`|  ,----'|  |_)  |      /  ^  \    |  |__   `---|  |----`
|  |  |  ||  |  |  |       |  |       >   <       |  |     |  |     |      /      /  /_\  \   |   __|      |  |     
|  '--'  ||  '--'  |       |  |      /  .  \      |  |     |  `----.|  |\  \----./  _____  \  |  |         |  |     
|_______/ |_______/        |__|     /__/ \__\     |__|      \______|| _| `._____/__/     \__\ |__|         |__|
''')

    print("Let's format some stuff for our controls!")

    if args.rpzblacklist:
        print("Formatting domains for the RPZ blacklist...")
        print()
        domains_rpz_blacklist(args.rpzblacklist)
        print()
        print(f"Output written to {rpzblacklist_txt} :)")

    if args.ipblacklist:
        print("Formatting IPs for the IDP blacklist...")
        print()
        blacklist_ips(args.ipblacklist)
        print()
        print(f"Output file written to {ipblacklist_txt} :)")

    if args.rpzwhitelist:
        print("Formatting domains for the RPZ whitelist...")
        domains_rpz_whitelist(args.rpzwhitelist)
        print()
        print(f"Output file written to {rpzwhitelist_txt} :)")

    if args.ipwhitelist:
        print("Formatting IPs for IDP whitelist")
        print()
        whitelist_ips(args.ipwhitelist)
        print()
        print(f"Output file written to {ipwhitelist_txt} :)")
