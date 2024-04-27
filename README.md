Student IDs: Aryan Mathur am943, Miles Yang mjy9, John Yoo jsy12, Linnea Kuruvilla lck21

## Lab 3 RIP README

Current state:
- All required functions written:
  - sr_handlepacket() correct
  - send_rip_request() correct
  - send_rip_update() correct
  - update_routing_table() potential problems
- Routers converge, BUT there is an unknown error where 1-2 routers will turn off and I can't find why

We have all the code written for implementing the required functions for lab 3, however we currently are not passing any testcases. Below is a description of what he have written, tried to debug, and any other relevant information for each function.

### sr_handlepacket

We implemented handling RIP requests and responses correctly (sending RIP response when receiving RIP requests and updating routing table when receiving RIP responses). We also implemented sending ICMP packets when necessary (if either the receiving or destination interface of receiving router was down) and code to update subnet routing table entries correctly.

### send_rip_request

Using wireshark, we can see that this function sends the correct data in each RIP request and sends it correctly through each interface on the sending router.

### sr_rip_update

Using wireshark, we can see that the RIP response packet is being populated with the correct information and correctly being sent through each interface.

### sr_rip_timeout

In this function, we first check our routing table for expired entries using current time - updated time. Then we check the interfaces statuses looping through if list and using the sr_obtain_interface_status function. If the interface is down we remove the entry using metric=infinity, otherwise when the interface is up we see if we are directly connected based on routes in the routing table, otherwise we add a new entry. Lastly we send out the rip updates.

This function does not seem to run at all based on all of our testing and with many different debug statements and print statements. With one router the solution code still sends periodic updates using this function but our code even with one router never gets to this point.

### update_route_table

I believe this logic is close to correct, but there may be errors in logic for when a link goes down which we were not able to debug since the routers crashed for some reason.

**Logic of our function:**
for each RIP entry:
    if RIP_entry destination found in routing table:
        if RIP packet source is the next hop on in the routing table's existing path:
            update metric and time
        else:
            if the new path is shorter:
                update entire routing table entry
    else:
        add new entry
if any routing table entry changed:
    broadcast an RIP response

In this function we check all the entries of the RIP packet and increment the metrics. if RT doesn't contain distance to RIP entry's destination we add an entry to the routing table just like the timeout function, if RT contains a distance to the RIP entry's destination if RIP packet source is the current next hop to the destination we set metric to infinity, if the packet metric was smaller than our current route table metric we would update the routing table. Then for part two  ii. if RIP packet source is not the current next hop to the destination, we would again update our routing table if the metric was smaller. 

In testing this function, we were not able to get our routing table to converge and we noticed with two routers that they would keep incrementing their routing table. We verified this behavior using print statements and wireshark packet analysis.


Thank you for reading, and thank you to the TAs for trying to help :)
