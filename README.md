# SR-P4
Based on the INT information, redirect the paths for the source routing.

# Requirement
The program can be executed in the same path as https://github.com/p4lang/tutorials/tree/master/exercises/source_routing. 

1.After compiling p4 file, run ```python controller.py``` in another terminal;

2.The only difference is that In h1's xterm, to send a message from the client, run ```./send.py 10.0.2.2 "P4 is good"```.

# Debug Instruction
Unlike P4 tutorial did in mri exercise, i take the mri information out of ip option and define a seperate header for it. Thus, the pakcet can ignore the size limit defined by ip option. However, there are still bugs going on when implementing this...
