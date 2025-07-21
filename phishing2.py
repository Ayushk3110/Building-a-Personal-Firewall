#include <iostream>
#include <string>
#include <vector>
#include <algorithm> // For std::transform
#include <stdexcept> // For std::invalid_argument
#include <iomanip>   // For std::setw

// Helper function to convert string to lowercase
std::string toLower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c){ return std::tolower(c); });
    return s;
}

// --- 1. Packet Representation ---
// Represents a simplified network packet.
class Packet {
public:
    std::string source_ip;
    std::string dest_ip;
    std::string protocol; // e.g., "tcp", "udp", "icmp"
    int source_port;
    int dest_port;
    std::string direction; // "IN" or "OUT"

    Packet(const std::string& src_ip, const std::string& dst_ip,
           const std::string& proto, int src_port, int dst_port,
           const std::string& dir = "IN")
        : source_ip(src_ip), dest_ip(dst_ip), protocol(toLower(proto)),
          source_port(src_port), dest_port(dst_port), direction(toLower(dir)) {
        // Basic validation for ports
        if ((source_port != -1 && (source_port < 0 || source_port > 65535)) ||
            (dest_port != -1 && (dest_port < 0 || dest_port > 65535))) {
            throw std::invalid_argument("Invalid port number. Must be between 0 and 65535 or -1 for any.");
        }
    }

    std::string toString() const {
        std::string s_port = (source_port == -1) ? "Any" : std::to_string(source_port);
        std::string d_port = (dest_port == -1) ? "Any" : std::to_string(dest_port);
        return "Packet(SrcIP=" + source_ip + ", DstIP=" + dest_ip +
               ", Proto=" + protocol + ", SrcPort=" + s_port + ", DstPort=" + d_port +
               ", Dir=" + direction + ")";
    }
};

// --- 2. Firewall Rule Definition ---
// Defines a firewall rule.
class Rule {
public:
    std::string action;    // "ALLOW" or "DENY"
    std::string direction; // "in", "out", or "any"
    std::string protocol;  // "tcp", "udp", "icmp", or "any"
    std::string source_ip; // IP address or CIDR (e.g., "192.168.1.0/24") or "any"
    std::string dest_ip;   // IP address or CIDR or "any"
    int source_port;       // Port number or -1 for "any"
    int dest_port;         // Port number or -1 for "any"

    Rule(const std::string& act, const std::string& dir = "any",
         const std::string& proto = "any", const std::string& src_ip = "any",
         const std::string& dst_ip = "any", int src_port = -1, int dst_port = -1)
        : action(toLower(act)), direction(toLower(dir)), protocol(toLower(proto)),
          source_ip(src_ip), dest_ip(dst_ip), source_port(src_port), dest_port(dst_port) {
        // Basic validation for ports
        if ((source_port != -1 && (source_port < 0 || source_port > 65535)) ||
            (dest_port != -1 && (dest_port < 0 || dest_port > 65535))) {
            throw std::invalid_argument("Invalid port number in rule. Must be between 0 and 65535 or -1 for any.");
        }
    }

    // Simplified IP matching: checks for exact match or "any"
    // For real CIDR matching, a dedicated IP library or parsing would be needed.
    bool ip_matches(const std::string& rule_ip, const std::string& packet_ip) const {
        if (rule_ip == "any") {
            return true;
        }
        // Simplified CIDR check: just checks if packet_ip starts with rule_ip (e.g., "192.168." matches "192.168.1.100")
        // This is NOT a proper CIDR implementation but serves for basic simulation.
        if (rule_ip.find('/') != std::string::npos) {
            std::string base_ip = rule_ip.substr(0, rule_ip.find('/'));
            return packet_ip.rfind(base_ip, 0) == 0; // Check if packet_ip starts with base_ip
        }
        return rule_ip == packet_ip;
    }

    bool matches(const Packet& packet) const {
        // Check direction
        if (direction != "any" && direction != packet.direction) {
            return false;
        }
        
        // Check protocol
        if (protocol != "any" && protocol != packet.protocol) {
            return false;
        }

        // Check source IP
        if (!ip_matches(source_ip, packet.source_ip)) {
            return false;
        }
        
        // Check destination IP
        if (!ip_matches(dest_ip, packet.dest_ip)) {
            return false;
        }
        
        // Check source port
        if (source_port != -1 && source_port != packet.source_port) {
            return false;
        }
        
        // Check destination port
        if (dest_port != -1 && dest_port != packet.dest_port) {
            return false;
        }
        
        return true;
    }

    std::string toString() const {
        std::string s_port = (source_port == -1) ? "Any" : std::to_string(source_port);
        std::string d_port = (dest_port == -1) ? "Any" : std::to_string(dest_port);

        std::string rule_str = "Rule(Action=" + action;
        if (direction != "any") rule_str += ", Dir=" + direction;
        if (protocol != "any") rule_str += ", Proto=" + protocol;
        if (source_ip != "any") rule_str += ", SrcIP=" + source_ip;
        if (dest_ip != "any") rule_str += ", DstIP=" + dest_ip;
        if (source_port != -1) rule_str += ", SrcPort=" + s_port;
        if (dest_port != -1) rule_str += ", DstPort=" + d_port;
        rule_str += ")";
        return rule_str;
    }
};

// --- 3. Firewall Logic ---
class PersonalFirewall {
public:
    std::vector<Rule> rules;
    std::string default_policy; // "allow" or "deny"

    PersonalFirewall() : default_policy("deny") {} // Default to denying everything not explicitly allowed

    void add_rule(const Rule& rule) {
        rules.push_back(rule);
        std::cout << "Added rule: " << rule.toString() << std::endl;
    }

    std::string process_packet(const Packet& packet) {
        std::cout << "\nProcessing packet: " << packet.toString() << std::endl;
        for (const auto& rule : rules) {
            if (rule.matches(packet)) {
                if (rule.action == "allow") {
                    std::cout << "  -> Packet ALLOWED by rule: " << rule.toString() << std::endl;
                    return "ALLOWED";
                } else if (rule.action == "deny") {
                    std::cout << "  -> Packet DENIED by rule: " << rule.toString() << std::endl;
                    return "DENIED";
                }
            }
        }
        
        // If no rule matched, apply the default policy
        if (default_policy == "allow") {
            std::cout << "  -> Packet ALLOWED by default policy." << std::endl;
            return "ALLOWED";
        } else { // default_policy == "deny"
            std::cout << "  -> Packet DENIED by default policy." << std::endl;
            return "DENIED";
        }
    }
};

// --- Demonstration ---
int main() {
    std::cout << "--- Personal Firewall Simulation (C++) ---" << std::endl;

    PersonalFirewall firewall;

    // --- Define Firewall Rules ---
    // Rule 1: Allow all outgoing HTTP (port 80) and HTTPS (port 443) traffic
    firewall.add_rule(Rule("allow", "out", "tcp", "any", "any", -1, 80));
    firewall.add_rule(Rule("allow", "out", "tcp", "any", "any", -1, 443));

    // Rule 2: Allow incoming SSH (port 22) from a specific trusted IP range
    // Note: Simplified CIDR check. For full CIDR, use a dedicated library.
    firewall.add_rule(Rule("allow", "in", "tcp", "192.168.1.0/24", "any", -1, 22));

    // Rule 3: Deny all incoming traffic from a known malicious IP
    firewall.add_rule(Rule("deny", "in", "any", "1.2.3.4", "any", -1, -1));

    // Rule 4: Allow all internal network communication (e.g., LAN traffic)
    // Note: Simplified CIDR check.
    firewall.add_rule(Rule("allow", "any", "any", "192.168.0.0/16", "192.168.0.0/16"));

    // Rule 5: Deny all other incoming TCP traffic (more specific than default deny)
    firewall.add_rule(Rule("deny", "in", "tcp"));


    // --- Simulate Packets ---
    std::cout << "\n--- Simulating Packet Traffic ---" << std::endl;

    // Test Case 1: Outgoing HTTP (Should be ALLOWED by Rule 1)
    Packet packet1("192.168.1.100", "203.0.113.5", "tcp", 54321, 80, "OUT");
    firewall.process_packet(packet1);
    // std::this_thread::sleep_for(std::chrono::milliseconds(500)); // C++11 for sleep

    // Test Case 2: Incoming SSH from trusted source (Should be ALLOWED by Rule 2)
    Packet packet2("192.168.1.50", "192.168.1.100", "tcp", 22, 50000, "IN");
    firewall.process_packet(packet2);
    // std::this_thread::sleep_for(std::chrono::milliseconds(500));

    // Test Case 3: Incoming SSH from untrusted source (Should be DENIED by default policy, or Rule 5 if it matches first)
    Packet packet3("203.0.113.10", "192.168.1.100", "tcp", 22, 50000, "IN");
    firewall.process_packet(packet3);
    // std::this_thread::sleep_for(std::chrono::milliseconds(500));

    // Test Case 4: Incoming from malicious IP (Should be DENIED by Rule 3)
    Packet packet4("1.2.3.4", "192.168.1.100", "tcp", 12345, 8080, "IN");
    firewall.process_packet(packet4);
    // std::this_thread::sleep_for(std::chrono::milliseconds(500));

    // Test Case 5: Outgoing UDP (Should be DENIED by default policy as no rule allows it)
    Packet packet5("192.168.1.100", "8.8.8.8", "udp", 50000, 53, "OUT");
    firewall.process_packet(packet5);
    // std::this_thread::sleep_for(std::chrono::milliseconds(500));

    // Test Case 6: Internal network communication (Should be ALLOWED by Rule 4)
    Packet packet6("192.168.1.10", "192.168.1.20", "tcp", 40000, 50000, "IN");
    firewall.process_packet(packet6);
    // std::this_thread::sleep_for(std::chrono::milliseconds(500));

    // Test Case 7: Incoming ICMP (Should be DENIED by default policy)
    Packet packet7("8.8.4.4", "192.168.1.100", "icmp", -1, -1, "IN");
    firewall.process_packet(packet7);
    // std::this_thread::sleep_for(std::chrono::milliseconds(500));

    std::cout << "\n--- Firewall Simulation Complete ---" << std::endl;

    return 0;
}