# Server

### Compile 
 gcc -Wall -o server dnsserver.c
### Run
 ./server hosts

# Client

### Compile
 gcc -Wall -o query dnsquery.c

### Run
 ./query 127.0.0.1 www.example.com