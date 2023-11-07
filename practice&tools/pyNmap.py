import nmap
import os
import re

print("\n****************************************************************")
print(r"""______            _     _  ______                 _           _ 
        |-----|| ********|--\    /--|********** |  /  **************
        |     ||         |   \  /   |           | /
        |_____||         |    \/    |           |/\\
        |                |          |           |   \
        |++++++++++++++  |++++++    |+++++++    |    \
       ______            ____________     __________     ___________
      """)
print("****************************************************************")                         
print("****************************************************************")


scanner = nmap.PortScanner()

def port_scan(target):
    start,end = map(int,input("\nEnter start and end ports: \n").split(','))
    print(f"Starting port scan on {target} {start}-{end} ")
    for i in range(start,end):
        res = scanner.scan(target,str(i))
        res = res['scan'][target]['tcp'][i]['state']
        if res == 'open':
            print(f'Port {i} is {res}')

    else:
        print('Done scanning')

def hosts(target):
    print(f"\nStarting nmap host discovery for {target}\n")
    if "/" not in target:
        res = {}
        for i in range(1):
            r = os.system(f"nmap -sn {target}")
            if r == 0:
                print(f"{target} is up")
            else:
                print(f"{target} is down")

print("\nWhats Popping!")
target = input("\nEnter IP Adress/range: ")
t = int(input("""
    Enter type of scan u want to perform:\n
    1) Host Discovery
    2) Port Scan

> """))

if t == 1: hosts(target)
if t == 2: port_scan(target)