Two thread types:
- Main thread
- RX thread

Main run thread runs from main() and accepts new connections creating an RX thread for each connection.

RX thread has a primary data struct rx, which is only used on that thread.

The TX struct is used by the RX thread to register with other threads and with the global bus data. This structure is ref counted to ensure the memory and file descriptor aren't free'd while some code may be interacting with it. Any usage of the TX structure must be done with a valid refererence.

Global data is stored in the RCU structures. These are modified under the bus lock. Each RX thread holds an RCU reader that allows it to read the global data without any further locks.

No two TX locks should be held at the same time. TX locks can be held inside of the bus lock or RCU lock, but not the other way around.

The bus lock and RCU lock must not be held at the same time - nor is there a reason to do so.

TX structures are registered in a number of places:
- RCU data for registering the unique ID #
- RCU data for registering names
- RCU data for registering subscriptions against a name, bus signals or broadcast interfaces
- Another TX struct for registering a client or server request

The RCU data is only ref'd for registering the unique ID as the scope of this wraps the other use cases.

Refs are pulled for registering with another TX structure.

Refs are pulled to allow locks to be dropped IE to allow calls such as:
1. Lock RCU lock
2. Lookup and grab TX struct ptr
3. Ref TX struct
4. Unlock RCU lock
5. Lock TX struct
6. Send data to TX struct
7. Unlock TX structs

struct rx is never stored in any accesible location so that functions that take an rx argument can only be called on that rx thread.
