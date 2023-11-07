import nmap

scanner = nmap.PortScanner()
target = '127.0.0.1'

for i in range(1,101):
    res = scanner.scan(target,str(i))
    res = res['scan'][target]['tcp'][i]['state']
    if res == 'open':
        print(f'Port {i} is {res}')

else:print('Done with Scanning!!!')
