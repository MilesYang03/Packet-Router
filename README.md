## Lab 3 RIP README

We have all the code written for implementing the required functions for lab 3, however we currently are not passing any testcases. Below is a description of what he have written, tried to debug, and any other relevant information for each function.

### sr_handlepacket

In this function, we largely kept everything the same from lab 2. 

### send_rip_request

Here we build an RIP packet based on the architecture described in lectures and the lab document. We fill out the ethernet header, ip header and udp header. We also set the command to 1 for the rip packet and fill the entries with 0 for all fields in the entry. We thought to set afi to afi_net that’s one thing that would often drastically change our results. Finally we send the packet. After debugging with print statements send_rip_request would be sent three times per router which is correct for the broadcast specification. 

We weren’t really sure if there were any bugs in this function but we did notice in wireshark that with sr_solution, two rip request packets would be picked up but with our sr, we only saw one rip request packet on the router.

### sr_rip_update

Here we looped through the interface list and did a lot of the same things as rip_request such as building out the headers. For the actual packet information however we would refer to the routing table and based on either split horizon or metric == infinity entries we would fill out the rip_packet entries to match. Implementing split horizon specifically was causing us some problems and not allowing our routing table to fully converge when we had two routers sending responses back and forth. 

### sr_rip_timeout

In this function, we first check our routing table for expired entries using current time - updated time. Then we check the interfaces statuses looping through if list and using the sr_obtain_interface_status function. If the interface is down we remove the entry using metric=infinity, otherwise when the interface is up we see if we are directly connected based on routes in the routing table, otherwise we add a new entry. Lastly we send out the rip updates.

This function does not seem to run at all based on all of our testing and with many different debug statements and print statements. With one router the solution code still sends periodic updates using this function but our code even with one router never gets to this point.

### update_route_table

In this function we check all the entries of the RIP packet and increment the metrics. if RT doesn't contain distance to RIP entry's destination we add an entry to the routing table just like the timeout function, if RT contains a distance to the RIP entry's destination if RIP packet source is the current next hop to the destination we set metric to infinity, if the packet metric was smaller than our current route table metric we would update the routing table. Then for part two  ii. if RIP packet source is not the current next hop to the destination, we would again update our routing table if the metric was smaller. 

In testing this function, we were not able to get our routing table to converge and we noticed with two routers that they would keep incrementing their routing table. We verified this behavior using print statements and wireshark packet analysis.


