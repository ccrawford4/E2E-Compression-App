# E2E Standalone Application
Follow these steps to set up and run the standalone application capable of detecting compression over a network
## Overview
### Objective
The goal of this project is to create a multithreaded application capable of detecting end to end compression over a network. Knowledge of compression is helpful in identifying potential security vulnerabilites. This is due to the fact that if compression is detected over a network its likely the data being transmitted is not encrypted. This is helpful both for attackers but also members of the internet who want to keep their data safe.
### How It Works
The standalone application sends TCP SYN packets to a server on closed ports and listens for RST packets to be sent back. The client can use this information to check if the time it takes for high entropy data to reach a server differs from low entropy data. 
#### Steps
1. Client will send one head TCP SYN packet to the server
2. Client will send a stream of low entropy UDP packets to the server
3. Client will send a tail TCP SYN packet to the server
4. The client will be listening as it sends the data (using multithreading) and will stop once it receives both RST packets
5. The client will compare the times of when the RST packets were received in order to calcualte the overall stream time.
6. The client will then repeat steps 1-5 but this time with high entropy data in each UDP packet sent in the stream for step three.
7. The client will compare the low entropy versus high entropy data and if the stream times differ more than 1 millisecond or 0.100 seconds then the client will print out that compression has been detected. Otherwise no compression can be concluded and the client will print this out.
##### Note
In cases where RST packets have been lost then the client will print out "Failed to detect due to insufficent information."
## Using The Program
### Getting Started
1. Clone the repository
```bash
$ git clone git@github.com:ccrawford4/E2E-Compression-App.git
```
2. Navigate to the root directory
```bash
$ cd E2E-Compression-App
```
3. Configure the JSON parser by running the configure script (yes sudo privlidges are required)
```bash
$ sudo ./configure.sh
```
4. Navigate to the app directory
```bash
$ cd app
```
5. Change the myconfig.json file to ensure that it has the correct server IP address and other desired values. Here is an example of how it should look like
```json
{
  "server_ip": "192.168.80.4",
  "UDP_src_port_number": "9876",
  "UDP_dest_port_number": "8765",
  "TCP_HEADSYN_dest_port_number": "9999",
  "TCP_TAILSYN_dest_port_number": "8888",
  "TCP_PREPROB_port_number": "7777",
  "TCP_POSTPROB_port_number": "6666",
  "UDP_payload_size": "1000B",
  "measurement_time": "15",
  "UDP_packet_train_size": "6000",
  "UDP_packet_TTL": "225",
  "RST_timeout": "5"
}
```
6. Go back to the root directory
```bash
$ cd ..
```
7. Start the program by running the run.sh script
```bash
# Make sure to include the name of your JSON config file 
# located in the 'app' directory for the 
# second command line argument

# Usage: 
# ./run.sh client <config file name>.json

# Example:
$ ./run.sh client myconfig.json
```
### Result
The client will print out the results like so:
```bash
No Compression Detected!
```
Note: If compression is detected over the network the client will print this out accordingly
### Removing Object Files
The source code includes a script that allows you to clean up all the object files and executables produced during the compilation of the program
```bash
# To clean up the object files and executables:
$ ./clean.sh
```
