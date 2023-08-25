import os
import sys
from random import randint
import threading
import time


def run_script(dest_net, src_net, interface):
    while True:
        host_number = randint(1, 200)
        source_host = src_net + ".{}".format(host_number)
        dst_net_scan = dest_net + ".1-30"

        loopback_cmd = "ifconfig lo:{} {} netmask 255.255.255.0 up".format(host_number, source_host)

        scan_cmd = 'timeout 3 nmap -sS -Pn {} -p {} -T5 -v -v -n --max-retries 0 -S {} -e {}'.format(dst_net_scan, PORT, source_host, interface)
        print(loopback_cmd)
        print(scan_cmd)
        # exit()
        os.system(loopback_cmd)
        time.sleep(1)
        os.system(scan_cmd)


if __name__ == "__main__":
    PORT = 80

    if len(sys.argv) > 4:
        syn_per_second = int(sys.argv[3])
        number_of_threads = int(sys.argv[3]) / 2
        threads = list()
        outgoing_interface = sys.argv[4]

        for index in range(number_of_threads + 1):
            x = threading.Thread(target=run_script, args=(sys.argv[1].rsplit('.', 1)[0], sys.argv[2].rsplit('.', 1)[0], outgoing_interface),)
            threads.append(x)
            x.start()

        for index, thread in enumerate(threads):
            thread.join()

    else:
        print("Usage: python scan_slow_flood.py [dest_net] [source_net] [syn per seconds] [outgoing interface]\n Example: "
              "python scan_slow_flood.py 155.1.203.0 44.1.2.0 30 eth1")
        exit()

