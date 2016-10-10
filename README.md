# Your Robust Network Guard
Protecting your valuable assets from intrusions

Run
===
Use the following command to run the Guard Server:

```sudo python3 app.py```

    *Example output*    
    ```
    Checking Guard configuration
    Auto configure server
    Redirecting DNS queries to Guard
    Start monitoring DNS queries
    
    Incoming query from 130.215.219.234
    ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 14371
    ;; flags: qr aa rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0
    ;; QUESTION SECTION:
    ;vm4.cs4404.com.                IN      ANY
    ;; ANSWER SECTION:
    vm4.cs4404.com.         10      IN      AAAA    2604:a880:400:d0::ac9:e008
    ```

Testing
===
Use the following commands to perform DNS query:

1. Query A record

    ```dig vm4.cs4404.com @2604:a880:400:d0::ac9:e001```
    or
    ```dig vm4.cs4404.com A @2604:a880:400:d0::ac9:e001```

    *Example output*
    ```
    ; <<>> DiG 9.8.3-P1 <<>> vm4.cs4404.com @192.241.147.112
    ;; global options: +cmd
    ;; Got answer:
    ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 11128
    ;; flags: qr aa rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0
    
    ;; QUESTION SECTION:
    ;vm4.cs4404.com.			IN	A
    
    ;; ANSWER SECTION:
    vm4.cs4404.com.		10	IN	A	192.241.147.112
    
    ;; Query time: 60 msec
    ;; SERVER: 192.241.147.112#53(192.241.147.112)
    ;; WHEN: Sat Oct  8 17:16:42 2016
    ;; MSG SIZE  rcvd: 48
    ```
2. Query AAAA record
    ```dig vm4.cs4404.com AAAA @2604:a880:400:d0::ac9:e001```
    *Example output*
    ```
    ; <<>> DiG 9.8.3-P1 <<>> vm4.cs4404.com AAAA @192.241.147.112
    ;; global options: +cmd
    ;; Got answer:
    ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 43924
    ;; flags: qr aa rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0
    
    ;; QUESTION SECTION:
    ;vm4.cs4404.com.			IN	AAAA
    
    ;; ANSWER SECTION:
    vm4.cs4404.com.		10	IN	AAAA	2604:a880:400:d0::ac9:e006
    
    ;; Query time: 67 msec
    ;; SERVER: 192.241.147.112#53(192.241.147.112)
    ;; WHEN: Sat Oct  8 17:21:47 2016
    ;; MSG SIZE  rcvd: 60
    ```
2. Query A or AAAA record
```dig vm4.cs4404.com ANY @2604:a880:400:d0::ac9:e001```
   *Example output*
   ```
   ; <<>> DiG 9.8.3-P1 <<>> vm4.cs4404.com ANY @192.241.147.112
    ;; global options: +cmd
    ;; Got answer:
    ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 32907
    ;; flags: qr aa rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0
    
    ;; QUESTION SECTION:
    ;vm4.cs4404.com.			IN	ANY
    
    ;; ANSWER SECTION:
    vm4.cs4404.com.		10	IN	AAAA	2604:a880:400:d0::ac9:e00c
    
    ;; Query time: 73 msec
    ;; SERVER: 192.241.147.112#53(192.241.147.112)
    ;; WHEN: Sat Oct  8 17:22:25 2016
    ;; MSG SIZE  rcvd: 60
   ```

Use the following command to send out http request:
```wget -O - http://[2604:a880:400:d0::ac9:e001]:80```
```ssh cs4404@2604:a880:400:d0::ac9:e00e -p 2222```

# Currently added domains:
 - vm4.cs4404.com. # 16 IPs