# Personal Firewall Simulator (C++)

This project implements a basic personal firewall simulator in C++. It demonstrates how network packets can be filtered based on predefined rules, mimicking the behavior of a real-world firewall.

## Features

* **Packet Representation**: Defines a `Packet` class to simulate network packets with attributes like source/destination IP, protocol, ports, and direction (IN/OUT).
* **Firewall Rule Definition**: Implements a `Rule` class allowing the definition of firewall rules based on:
    * Action (`ALLOW` or `DENY`)
    * Direction (`in`, `out`, `any`)
    * Protocol (`tcp`, `udp`, `icmp`, `any`)
    * Source/Destination IP (supports exact IP or simplified CIDR matching like "192.168.1.0/24")
    * Source/Destination Port (specific port or `-1` for any)
* **Firewall Logic**: The `PersonalFirewall` class manages a set of rules and a default policy (`allow` or `deny`). It processes incoming packets against the rules in order, applying the first matching rule's action. If no rule matches, the default policy is applied.
* **Rule Prioritization**: Rules are processed in the order they are added. The first rule that matches a packet determines the action.
* **Simplified CIDR Matching**: Includes a basic implementation for CIDR matching (e.g., "192.168.1.0/24") which checks if the packet IP starts with the base IP of the rule. **Note: This is a simplified approach and not a full, RFC-compliant CIDR implementation.**

## How it Works

The firewall operates on a simple principle:

1.  **Packet Definition**: A `Packet` object encapsulates all relevant information about a network packet.
2.  **Rule Definition**: `Rule` objects specify criteria for matching packets and an action to take (`allow` or `deny`).
3.  **Rule Processing**: When a packet arrives, the `PersonalFirewall` iterates through its list of `Rule`s.
4.  **First Match Wins**: The first `Rule` that completely matches the packet's attributes is applied.
5.  **Default Policy**: If no rules match the packet, a predefined default policy (e.g., "deny all") is enforced.

## Getting Started

### Prerequisites

* A C++ compiler (e.g., g++).

### Compiling the Code

1.  Save the provided code as `firewall_simulator.cpp` (or any `.cpp` extension).
2.  Open a terminal or command prompt.
3.  Navigate to the directory where you saved the file.
4.  Compile the code using your C++ compiler. For g++, use:

    ```bash
    g++ firewall_simulator.cpp -o firewall_simulator -std=c++11
    ```
    (The `-std=c++11` flag is used for `std::transform` and `std::chrono` if you uncomment the sleep calls, though they are commented out in the provided code).

### Running the Simulator

After successful compilation, run the executable:

```bash
./firewall_simulator
