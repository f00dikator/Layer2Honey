# Layer2Honey
The start of a Layer 2 honeypot

This honeypot should:
1) Never initiate traffic above layer 2
2) Be able to find all Mac addrs on a broadcast domain and enumerate them
3) Map all live Macs to the most current live IP 
4) insert our mac into the arp cache of all domain machines every 30 seconds
5) alert when we get arp probes (arp who-has for our IP)
6) alert when we get a packet that is destined for layer 3 and above

Optional:
maintain a list of ports that we will alert on if #6 occurs
setup pseudo listeners for ports from above
perhaps flag on all dstPort < 1024


To Run:
./MacHoney -config config.yml

Config.yml needs:
  - interface (string)
  - interface IP (string)
  - interface MAC (string)
  - gateway MAC (string) ... e.g. the Mac addr of the default gateway which proxy arps...don't want that...
