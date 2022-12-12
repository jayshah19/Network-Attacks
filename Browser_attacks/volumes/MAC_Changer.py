import subprocess
import optparse
import re


def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-i", "--interface", dest="interface", help="Interface to change its MAC address")
    parser.add_option("-m", "--mac", dest="new_MAC", help="new MAC address")
    (options, arguments) = parser.parse_args()
    if not options.interface:
        parser.error("[-] Please specify an interface, use --help for more info.")
    elif not options.new_MAC:
        parser.error("[-] Please specify a new MAC, use --help for more info.")
    return options


def change_MAC(interface, new_MAC):
    print("[+] Changing MAC address for " + interface + " to " + new_MAC)
    subprocess.call(["ifconfig", interface, "down"])
    subprocess.call(["ifconfig", interface, "hw", "ether", new_MAC])
    subprocess.call(["ifconfig", interface, "up"])


def get_current_mac(interface):
    inconfig_result = subprocess.check_output(["ifconfig", interface])
    mac_address_search_result = re.search(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w", inconfig_result.decode("utf-8"))

    if mac_address_search_result:
        return mac_address_search_result.group(0)
    else:
        print("[-] Could not read MAC address")


options = get_arguments()
current_mac = get_current_mac(options.interface)
print("Current MAC: " + str(current_mac))

change_MAC(options.interface, options.new_MAC)

current_mac = get_current_mac(options.interface)
if current_mac == options.new_MAC:
    print("[+] MAC Address was successfully changed to " + current_mac)
else:
    print("[-] MAC Address did not get changed.")