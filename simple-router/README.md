Zhicheng Ren

○ The high level design of your implementation (< 1 page)

When there is a arp request being send to the router, the router reply with a packet containing its mac address.

When there is a packet being sent to the router itself, it generates an icmp echo reply to the sender.

When there is a packet being sent to another host, the router passes it to that host. If the router cannot reach the host.

When the router does not know about the next-hop mac address, it send an arp request to the corresponding IP and wait for an arp reply.

Before it receives an arp reply, it queue the messages to be sent later.

An arp cache is built such that if messages are sent repeatedly to one host, it does not have to send another arp message.

○ The problems you ran into and how you solved the problems (< 1 page)

When using mactostring function, all 1's maps to ff:ff:ff:ff:ff:ff:ff:ff instead of FF:FF:FF:FF:FF:FF:FF:FF, which is more intuitive.

Trouble in replying from an icmp message which is not send to the interface itself but another interface in the router, using findfacebyip != nullptr.

Trouble in cast a const pointer to a pointer, using explicit cast, which is (RoutingTableEntry* ) cast.

checksum for the icmp header, need to copy twice.
