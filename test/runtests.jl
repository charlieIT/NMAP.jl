#=

s = NMAP.Scanner(
           NMAP.ports("80", "22"),
           "-O",
           "-sV",
           NMAP.targets("127.0.0.1"))

s = NMAP.Scanner(
           NMAP.ports("80", "22"),
           "-O",
           "-sV",
           NMAP.targets("127.0.0.1", "192.168.80.2"))

=#
