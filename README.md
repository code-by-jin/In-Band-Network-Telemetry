# SR-P4
The objective of this repository is to implement Source Routing and In-Band Network Telemetry. Sepcifically, the host guides each switch in the network to send the packet to a specific port and track the status of the switch that every packet travels through.  


# Requirement
The program can be executed in the same path as https://github.com/p4lang/tutorials/tree/master/exercises/source_routing. 

1.After compiling p4 file, run ```python controller.py``` in another terminal;

2.The only difference is that In h1's xterm, to send a message from the client, run ```./send.py 10.0.2.2 "P4 is good"```.

# Acknowledgement
Thanks for the help from the P4 community, especially from Tu Dang and Xin Zhe.


