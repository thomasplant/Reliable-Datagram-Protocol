# Reliable-Datagram-Protocol


Reliable Datagram Protocol or RDP is closely implemented for TCP-like data transfer.

This program takes an input file and sends it to an echo server using UDP. Once the data is returned to the program via the echo server, the program processes the data implementing the go-back N protocol and writes the contents to an output file.

The program will SYN and FIN the connection and sends all the data in 1024 byte payloads. This can be shown in the .cap files above. eth0 is before the error, and eth1 would be after the error, and delay is added to each packet.

This program has hardcoded addresses and ports, so running this on other devices requires modification.
