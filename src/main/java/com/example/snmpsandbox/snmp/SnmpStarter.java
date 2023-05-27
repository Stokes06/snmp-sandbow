package com.example.snmpsandbox.snmp;

import lombok.extern.slf4j.Slf4j;
import org.snmp4j.Snmp;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

@Component
@Slf4j
public class SnmpStarter implements CommandLineRunner {

    private final Snmp snmp;

    public SnmpStarter(Snmp snmp) {
        this.snmp = snmp;
    }

    @Override
    public void run(String... args) throws Exception {
        log.info("Starting snmp agent...");
        snmp.listen();
    }
}
