package com.example.snmpsandbox.snmp;

import lombok.extern.slf4j.Slf4j;
import org.snmp4j.*;
import org.snmp4j.event.AuthenticationFailureEvent;
import org.snmp4j.event.AuthenticationFailureListener;
import org.snmp4j.log.ConsoleLogAdapter;
import org.snmp4j.log.ConsoleLogFactory;
import org.snmp4j.log.LogFactory;
import org.snmp4j.mp.*;
import org.snmp4j.security.*;
import org.snmp4j.smi.Address;
import org.snmp4j.smi.OctetString;
import org.snmp4j.smi.UdpAddress;
import org.snmp4j.smi.VariableBinding;
import org.snmp4j.transport.DefaultUdpTransportMapping;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.io.IOException;

@Configuration
@Slf4j
public class SnmpConfiguration {

    static {
        // This allows SNMP logging
        LogFactory.setLogFactory(new ConsoleLogFactory());
        ConsoleLogAdapter.setDebugEnabled(true);
    }

    private static <A extends Address> void sendResponse(CommandResponderEvent<A> event, PDU pdu) {
        try {
            event.getMessageDispatcher().returnResponsePdu(event.getMessageProcessingModel(),
                    event.getSecurityModel(), event.getSecurityName(), event.getSecurityLevel(),
                    pdu, event.getMaxSizeResponsePDU(), event.getStateReference(), new StatusInformation());
        } catch (MessageException e) {
            log.error("Error while sending response: {}", e.getMessage());
        }
    }

    @Bean
    Snmp snmp() throws IOException {
        MessageDispatcherImpl dispatcher = new MessageDispatcherImpl();
        dispatcher.addMessageProcessingModel(new MPv1());
        dispatcher.addMessageProcessingModel(new MPv2c());
        dispatcher.addMessageProcessingModel(new MPv3());
        var snmp = new Snmp(dispatcher, new DefaultUdpTransportMapping(new UdpAddress("0.0.0.0/161")));

        SecurityProtocols.getInstance().addDefaultProtocols();
        SecurityProtocols.getInstance().addAuthenticationProtocol(new AuthMD5());
        SecurityProtocols.getInstance().addAuthenticationProtocol(new AuthSHA());

        USM usm = new USM(SecurityProtocols.getInstance(), new OctetString("800007DB03360102101100"), 0);
        SecurityModels.getInstance().addSecurityModel(usm);
        dispatcher.addAuthenticationFailureListener(new AuthenticationFailureListener() {
            @Override
            public <A extends Address> void authenticationFailure(AuthenticationFailureEvent<A> event) {
                log.warn("failed to authenticate {}", event);
            }
        });

        snmp.getUSM().addUser(
                new OctetString("manager"),
                new UsmUser(new OctetString("manager"),
                        SnmpConstants.usmHMACMD5AuthProtocol,
                        new OctetString("password"),
                        SnmpConstants.usmDESPrivProtocol,
                        new OctetString("password")
                )
        );


        snmp.addCommandResponder(new CommandResponder() {
            @Override
            public <A extends Address> void processPdu(CommandResponderEvent<A> event) {
                log.info("Received event {}", event);

                ScopedPDU pdu = (ScopedPDU) event.getPDU();
                if (event.getPDU().getType() != PDU.GET) {
                    log.warn("Only support GET requests for now");
                    pdu.setErrorStatus(PDU.readOnly);
                    sendResponse(event, pdu);
                    return;
                }

                pdu.setType(PDU.RESPONSE);
                pdu.setErrorStatus(PDU.noError);

                // fill PDU variables with random values
                for (VariableBinding variableBinding : event.getPDU().getAll()) {
                    variableBinding.setVariable(new OctetString("1"));
                }

                sendResponse(event, pdu);
            }
        });

        return snmp;
    }


}

