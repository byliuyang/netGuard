$TTL    3600
@       IN      SOA     ns1.cs4404.com. ns2.cs4404.com. (
                  7     ; Serial
               3600     ; Refresh
               3600     ; Retry
               3600     ; Expire
             604800 )   ; Negative Cache TTL
;
; name servers - NS records
     IN      NS      ns1.cs4404.com.
     IN      NS      ns1.cs4404.com.

; name servers - A records
ns1.cs4404.com.          IN      A       127.0.0.1
ns1.cs4404.com.          IN      A       127.0.0.1

; 10.128.0.0/16 - A records
vm4.cs4404.com.          IN      A       192.241.147.112
vm4.cs4404.com.          IN      AAAA    2604:a880:400:d0::ac9:e000
vm4.cs4404.com.          IN      AAAA    2604:a880:400:d0::ac9:e001
vm4.cs4404.com.          IN      AAAA    2604:a880:400:d0::ac9:e002
vm4.cs4404.com.          IN      AAAA    2604:a880:400:d0::ac9:e003
vm4.cs4404.com.          IN      AAAA    2604:a880:400:d0::ac9:e004
vm4.cs4404.com.          IN      AAAA    2604:a880:400:d0::ac9:e005
vm4.cs4404.com.          IN      AAAA    2604:a880:400:d0::ac9:e006
vm4.cs4404.com.          IN      AAAA    2604:a880:400:d0::ac9:e007
vm4.cs4404.com.          IN      AAAA    2604:a880:400:d0::ac9:e008
vm4.cs4404.com.          IN      AAAA    2604:a880:400:d0::ac9:e009
vm4.cs4404.com.          IN      AAAA    2604:a880:400:d0::ac9:e00a
vm4.cs4404.com.          IN      AAAA    2604:a880:400:d0::ac9:e00b
vm4.cs4404.com.          IN      AAAA    2604:a880:400:d0::ac9:e00c
vm4.cs4404.com.          IN      AAAA    2604:a880:400:d0::ac9:e00d
vm4.cs4404.com.          IN      AAAA    2604:a880:400:d0::ac9:e00e
vm4.cs4404.com.          IN      AAAA    2604:a880:400:d0::ac9:e00f
