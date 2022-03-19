Create a `Scanner` to scan `scanme.nmap.org` with OS detection, version detection, script scanning, and traceroute with Timing template 4.

```julia
scanner = NMAP.Scanner("-A", "-T4", "scanme.nmap.org")
```

Invoking `run!` will mutate the scanner. For instance, output format and outputfile are automatically defined within run!

By default, run! will add `-oX option` to the scanner to force generation of XML output.

**Note**: Some nmap options prevent or otherwise hinder the possibility of generating correct XML

```julia
scan = NMAP.run!(scanner)
```

