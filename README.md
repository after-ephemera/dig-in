# dig-in
A simple DNS Server in C.

### Have you ever just wanted be able to run the `dig` command and resolve your own dns queries in linear time? 
... if so you're in luck!

Dig In is a relatively dumb DNS server (I know it's redundant, Jack) provided here to prove that a linear search isn't so bad
when you only have a handful of elements. Also to demonstrate the handling of DNS queries and assembly of DNS responses.

So at the end of the day, Dig In handles CNAME and A Records. 

That's it.

To test the server, `make` the project, then run the following command.
- `dig +noedns -p 8080 @127.0.0.1 your-url-here.com`
