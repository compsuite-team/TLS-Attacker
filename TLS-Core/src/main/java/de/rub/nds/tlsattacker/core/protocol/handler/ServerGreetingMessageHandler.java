/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2020 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.ServerCapability;
import de.rub.nds.tlsattacker.core.constants.StarttlsType;
import de.rub.nds.tlsattacker.core.protocol.message.ServerGreetingMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.ServerGreetingMessageParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.ServerGreetingMessagePreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.ServerGreetingMessageSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.LinkedList;
import java.util.List;

public class ServerGreetingMessageHandler extends EmailProtocolMessageHandler<ServerGreetingMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ServerGreetingMessageHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public ServerGreetingMessageParser getParser(byte[] message, int pointer) {
        return new ServerGreetingMessageParser(pointer, message, tlsContext.getChooser().getLastRecordVersion(),
                tlsContext.getConfig());
    }

    @Override
    public ServerGreetingMessagePreparator getPreparator(ServerGreetingMessage message) {
        return new ServerGreetingMessagePreparator(tlsContext.getChooser(), message);
    }

    @Override
    public ServerGreetingMessageSerializer getSerializer(ServerGreetingMessage message) {
        return new ServerGreetingMessageSerializer(message, tlsContext.getChooser().getLastRecordVersion());
    }

    @Override
    public void adjustTLSContext(ServerGreetingMessage message) {
        StarttlsType type = tlsContext.getConfig().getStarttlsType();
        String readableMessage = ArrayConverter.bytesToHexString(message.getMessage());
        String[] parts = readableMessage.split(" |\\r?\\n"); // Split string on
                                                             // space and new
                                                             // line.

        // TODO: Wird überprüfung von SMTP und POP3 Greeting benötigt?
        if (type == StarttlsType.IMAP) { // TOOO: Wird Preauth im
                                         // Contextbenötigt? if
                                         // ("PREAUTH".equals(parts[1]))
            tlsContext.setIsPreauth(true);
            if (parts[2] != null && parts[2].startsWith("[")) {
                tlsContext.setCapaInGreeting(true);
                List<ServerCapability> capabilities = new LinkedList<ServerCapability>();
                for (int i = 2; i < parts.length; i++) {
                    String capability = parts[i];
                    if (capability.startsWith("["))
                        capability = capability.substring(1);
                    if (capability.endsWith("]"))
                        capability = capability.substring(0, capability.length() - 1);
                    ServerCapability capa = ServerCapability.getCapabilityFromString(type, capability);
                    if (capa != null)
                        capabilities.add(capa);
                }
                tlsContext.setServerCapabilities(capabilities);
            }
        }

    }
}
