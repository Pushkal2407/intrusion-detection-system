# Intrusion Detection System

This project implements a multithreaded Intrusion Detection System (IDS) that monitors network traffic for potential security threats. It can detect SYN flood attacks, ARP cache poisoning attempts, and blacklisted URL accesses.

## Components

The system consists of several interconnected modules:

1. `main.c`: The entry point of the program, handling command-line arguments.
2. `sniff.c`: Responsible for capturing network packets.
3. `dispatch.c`: Manages worker threads and packet distribution.
4. `pqueue.c`: Implements a thread-safe packet queue for inter-thread communication.
5. `analysis.c`: Performs the actual intrusion detection analysis on packets.

## Multithreaded Architecture

This IDS utilizes a multithreaded architecture to efficiently process network packets:

1. **Main Thread**: Handles packet capture (in `sniff.c`). It captures packets from the network interface and dispatches them to worker threads.
2. **Worker Threads**: Multiple worker threads (defined in `dispatch.c`, default is 10) process packets concurrently. Each worker thread:
   - Retrieves packets from the shared queue
   - Performs analysis on each packet
   - Updates shared data structures with results
3. **Thread-Safe Queue**: Implemented in `pqueue.c`, this queue allows safe communication between the main thread and worker threads. It uses mutex locks and condition variables to ensure thread-safety.
4. **Synchronization**: The system uses various mutex locks (in `analysis.c`) to protect shared data structures and ensure thread-safe updates of detection statistics.

This multithreaded design offers several advantages:
- Improved performance through parallel processing of packets
- Better utilization of multi-core processors
- Ability to handle high-volume network traffic

## Features

1. SYN Flood Detection: Monitors for an unusual number of SYN packets from different IP addresses.
2. ARP Cache Poisoning Detection: Tracks ARP responses to identify potential cache poisoning attempts.
3. Blacklisted URL Detection: Checks for access to predefined blacklisted URLs (currently set to www.google.co.uk and www.bbc.co.uk for demonstration purposes).

## Prerequisites

To build and run this project, you need:
- GCC compiler
- libpcap development files
- POSIX threads library

On Ubuntu or Debian-based systems, you can install these with:
sudo apt-get install build-essential libpcap-dev

## Building the Project

The project includes a Makefile for easy compilation. To build the project, run:
make
This will compile all source files and create an executable named `idsniff`.

To clean the build files:
make clean

## Running the Intrusion Detection System

To run the IDS, use the following command:
sudo ./idsniff [OPTIONS]
The program requires root privileges to capture packets.

### Command-line Options

Refer to `main.c` for the exact command-line options available. Common options include:
- `-i [interface]`: Specify the network interface to monitor
- `-v`: Enable verbose mode for debugging

Example: sudo ./idsniff -i eth0 -v

## Output

The program displays real-time alerts for detected intrusions. When interrupted (e.g., with Ctrl+C), it prints a summary report of detected threats.

## Limitations and Future Improvements

- The number of worker threads is currently fixed. Future versions could make this configurable or dynamically adjustable based on system load.
- Packet processing is relatively simple. More sophisticated analysis techniques could be implemented for better threat detection.
- While multithreading improves performance, very high traffic volumes might still overwhelm the system. Future versions could implement more advanced load balancing or packet sampling techniques.

