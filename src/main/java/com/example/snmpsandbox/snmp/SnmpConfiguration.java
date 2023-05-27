package com.example.snmpsandbox.snmp;

import lombok.extern.slf4j.Slf4j;
import org.snmp4j.*;
import org.snmp4j.log.ConsoleLogAdapter;
import org.snmp4j.log.ConsoleLogFactory;
import org.snmp4j.log.LogFactory;
import org.snmp4j.mp.StatusInformation;
import org.snmp4j.smi.Address;
import org.snmp4j.smi.OctetString;
import org.snmp4j.smi.UdpAddress;
import org.snmp4j.smi.VariableBinding;
import org.snmp4j.transport.DefaultUdpTransportMapping;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.io.IOException;
import java.security.SecureRandom;

@Configuration
@Slf4j
public class SnmpConfiguration {

    static {
        // This allows SNMP logging
        LogFactory.setLogFactory(new ConsoleLogFactory());
        ConsoleLogAdapter.setDebugEnabled(true);
    }

    private static <A extends Address> PDU buildPduFromEvent(CommandResponderEvent<A> event) {
        var pdu = new PDU();
        // Very important to keep the original request id, otherwise response will be ignored by the monitoring application
        pdu.setRequestID(event.getPDU().getRequestID());
        pdu.setType(PDU.RESPONSE);
        return pdu;
    }

    private static <A extends Address> void sendResponse(CommandResponderEvent<A> event, PDU pdu) {
        try {
            event.getMessageDispatcher().returnResponsePdu(event.getMessageProcessingModel(),
                    event.getSecurityModel(), event.getSecurityName(), event.getSecurityLevel(),
                    pdu, event.getMaxSizeResponsePDU(), event.getStateReference(), new StatusInformation());
        } catch (MessageException e) {
            System.err.println("Error while sending response: " + e.getMessage());
        }
    }

    @Bean
    Snmp snmp() throws IOException {
        var snmp = new Snmp(new DefaultUdpTransportMapping(new UdpAddress("0.0.0.0/161")));

        snmp.addCommandResponder(new CommandResponder() {
            @Override
            public <A extends Address> void processPdu(CommandResponderEvent<A> event) {
                log.info("Received event {}", event);

                PDU pdu = buildPduFromEvent(event);
                if (event.getPDU().getType() != PDU.GET) {
                    log.warn("Only support GET requests for now");
                    pdu.setErrorStatus(PDU.readOnly);
                    sendResponse(event, pdu);
                    return;
                }

                pdu.setErrorStatus(PDU.noError);

                // fill PDU variables with random values
                for (VariableBinding variableBinding : event.getPDU().getAll()) {
                    pdu.add(new VariableBinding(variableBinding.getOid(), new OctetString(String.valueOf(new SecureRandom().nextInt()))));
                }
                sendResponse(event, pdu);
            }
        });

        return snmp;
    }


}

