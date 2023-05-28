## SNMP4j example to receive command and respond

This application is a Spring Boot application.

It will start an SNMP agent using UDP protocol on port 161.

To send command to the agent, install the
CLI : [Link to download binaries for Windows](https://sourceforge.net/projects/net-snmp/files/net-snmp%20binaries/5.5-binaries/)

examples of commands :

- Execute a GET command

```bash
snmpget -v3  -l authPriv -u manager -a MD5 -A password  -x DES -X password  172.24.208.1 1.3.1.1.1
```

- Execute a SET command

```bash
snmpset -v1 -c "public" -r 0 -t 30 127.0.0.1 1.3.6.1.2.1.1.1 = 1
```

