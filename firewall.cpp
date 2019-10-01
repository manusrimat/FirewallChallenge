#include <iostream>
#include <fstream>
#include <string>
#include <list>
#include <unordered_map>
#include <arpa/inet.h>
#include <sstream>
#include <utility>

using namespace std;

// 32-bit unsigned int max is == integer value of IP address 255.255.255.255 == 4294967295.

typedef pair<int, int> PortRange;
template<> struct hash<PortRange*> {
  size_t operator()(PortRange* p) const {
    hash<int> h = hash<int>();
    return h(p->first);
  }
};

typedef pair<unsigned int, unsigned int> IPRange;
typedef hash<PortRange*> PortRangeHasher;
typedef unordered_map<PortRange*, IPRange*, PortRangeHasher> PortIPMap;
typedef unordered_map<string, PortIPMap*> ProtoPortMap;
typedef unordered_map<string, ProtoPortMap*> DirProtoMap;

class Firewall {
  private:
    DirProtoMap dirProtoMap;

    unsigned int addrToDecimal(string addr) {
      unsigned int decimalVal = 0;
      inet_pton(AF_INET, addr.c_str(), &decimalVal);
      decimalVal = ntohl(decimalVal);
      return decimalVal;
    }

    void addFirewallRule(string rule) {
      // cout << "Addinig rule " << rule << "\n";
      istringstream lineStream(rule);
      string dir, proto, ports, ips;
      getline(lineStream, dir, ',');
      getline(lineStream, proto, ',');
      getline(lineStream, ports, ',');
      getline(lineStream, ips, ',');

      ProtoPortMap* protoPortMap = dirProtoMap[dir];
      if (protoPortMap == NULL) {
        protoPortMap = new ProtoPortMap();
        dirProtoMap[dir] = protoPortMap;
      }
      PortIPMap* portIPMap = (*protoPortMap)[proto];
      if (portIPMap == NULL) {
        portIPMap = new PortIPMap();
        (*protoPortMap)[proto] = portIPMap;
      }

      PortRange *portRange = new PortRange();
      if (ports.find_first_of('-') == string::npos) {
        int port = stoi(ports);
        *portRange = make_pair(port, port);
      } else {
        istringstream range(ports);
        string start, end;
        getline(range, start, '-');
        getline(range, end, '-');
        *portRange = make_pair(stoi(start), stoi(end));
      }
      
      IPRange *ipRange = new IPRange();
      if (ips.find_first_of('-') == string::npos) {
        unsigned int addr = addrToDecimal(ips);
        *ipRange = make_pair(addr, addr);
      } else {
        istringstream range(ips);
        string start, end;
        getline(range, start, '-');
        getline(range, end, '-');
        *ipRange = make_pair(addrToDecimal(start), addrToDecimal(end));
      }
      portIPMap->insert(make_pair(portRange, ipRange));
    }

    bool portInRange(PortRange *range, int port) {
      // cout << "Checking for port " << port << " in range " << pairToString(range) << "\n";
      return port >= range->first && port <= range->second;
    }

    bool ipInRange(IPRange *range, int addr) {
      // cout << "Checking for IP " << (unsigned int)addr << " in range " << pairToString(range) << "\n";
      return addr >= range->first && addr <= range->second;
    }

    string pairToString(PortRange *range) {
      return "[" + to_string(range->first) + ", " + to_string(range->second) + "]";
    }

    string pairToString(IPRange *range) {
      return "[" + to_string(range->first) + ", " + to_string(range->second) + "]";
    }

  public:
    Firewall(const char* rulesFilePath) {
      // Read the csv file one line at the time
      ifstream rulesFile;
      rulesFile.open(rulesFilePath);
      string line;
      while(true) {
        rulesFile >> line;
        if(rulesFile.eof()) break;
        addFirewallRule(line);
      }
      rulesFile.close();
    }

    ~Firewall() {
      // free all memory here
    }

    bool accept_packet(string dir, string proto, unsigned int port, string ip) {
      ProtoPortMap *protoPortMap = dirProtoMap[dir];
      if (protoPortMap == NULL) {
        cout << "Not in direction protocol map";
        return false;
      }

      PortIPMap *portIPMap = (*protoPortMap)[proto];
      if (portIPMap == NULL) {
        cout << "Not in protocol port map";
        return false;
      }

      unsigned int addr = addrToDecimal(ip);
      for (PortIPMap::iterator it = begin(*portIPMap); it != end(*portIPMap); ++it) {
        PortRange *portRange = it->first;
        IPRange *ipRange = it->second;
        if (portInRange(portRange, port) && ipInRange(ipRange, addr)) {
          return true;
        }
      }

      return false;
    }
};

int main(int argc, char** argv) {
  if (argc < 6) {
    cerr << "Usage: " << argv[0] << " <rules file> <test dir> <test proto> <test port> <test ip>" << "\n";
    exit(-1);
  }

  Firewall firewall(argv[1]);

  string dir = argv[2];
  string proto = argv[3];
  unsigned int port = stoi(argv[4]);
  string ip = argv[5];
  
  bool allow = firewall.accept_packet(dir, proto, port, ip);
  cout << (allow ? "allow" : "deny") << "\n";
  return 0;
}
