# SR-P4  
The objective of this repository is to implement In-Band Network Telemetry. Once the end host receive the packet, it will deparse the packet and send the INT information back to the sender. 

# Requirement
The program can be executed in the same path as https://github.com/p4lang/tutorials/tree/master/exercises/source\_routing. 

1.After compiling p4 file, in another terminal, run ```cd triangle-topo``` and then run ```python controller.py```;

2.In h2's terminal, run ```python receive.py``` 

3.In h1's terminal, run ```python send.py 10.0.2.2 100``` to send 100 packets to h2


# Acknowledgement
Thanks for the help from the P4 community, especially from Tu Dang and Xin Zhe.


