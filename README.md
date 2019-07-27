# eqt-server
EDNS0 Query Target Authoritative server implementation

## Requirements
- [Python3](https://python.org/)
- [dnspython](http://www.dnspython.org/)
  -- `apt install python3-dnspython -y`

## Usage
`sudo ./eqt-server.py config.conf`

## config.conf example
```
[default]
example.com = /var/zones/default/example.com.zone
example.net = /var/zones/default/example.net.zone

```

## Configuration Guide
<PRE>
;;;
;;; [global] clause specifies global setting of eqt-server.
;;;
<b>[global]</b>
;; listening port
port = 53

;; If logfile is specified, eqt-server writes log to the file.
;; Otherwise writes to stderr.
;logfile = eqt.log

;;;
;;; Zone definitions
;;;
;; [default] clause specifies zones in "default" virtual host.

<b>[default]</b>
; &lt;zonename&gt; = &lt;path-to-zonefile&gt;
<b>example.com = /var/zones/default/example.com.zone</b>
<b>example.net = /var/zones/default/example.net.zone</b>
<b>sub.example.net = /var/zones/default/sub.example.net.zone</b>

;;
;; Zone definitions for virtual hosts.
;;
; If incoming DNS query containis EDNS0 query target hostname (QTH),
; eqt-server uses zones in "virtual host" maching the QTH for response.
; If no virtual hostname matches or no QTH, zones in [default] are used.

<b>[virtualhost1.dnsprovider.com]</b>
;mydomain.com = /var/zones/virtualhost1/mydomain.com.zone

<b>[virtualhost2.dnsprovider.com]</b>
;mydomain2.com = /var/zones/virtualhost2/mydomain2.com.zone
<PRE>

