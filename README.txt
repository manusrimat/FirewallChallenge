I used my Mac OS X machine to build and test.

Compile:
  g++ -o firewall firewall.cpp

Run:
  ./firewall ./fw.csv inbound tcp 65536 2.2.2.2

See usage:
  ./firewall

Optimizations:
  For each of direction and protocol combination I would keep an ordered list of ports and
  abort checking once the lower bound is greater than the port I am looking for.
  It can be iterative from top which would still be O(N) but can be binary searched (with a custom comparator) for O(log N)

Testing:
  A test driver is part of the firewall.cpp file, (the main function), it accepts one test case
  The rules file I created includes both sample rules and my own.
  These rules exercise every line of constructor and the functions it calls.
  For each rule I manually ran from command line looking for "allow" for each rule and looking for "deny" by
  mixing all 4 of them (dir, proto, port & IP) from other rules.
