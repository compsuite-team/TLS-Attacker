/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2020 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator;

import de.rub.nds.tlsattacker.core.constants.ServerCapability;
import de.rub.nds.tlsattacker.core.constants.StarttlsType;
import de.rub.nds.tlsattacker.core.exceptions.PreparationException;
import de.rub.nds.tlsattacker.core.protocol.message.ServerGreetingMessage;
import de.rub.nds.tlsattacker.core.protocol.preparator.EmailProtocolMessagePreparator;
import de.rub.nds.tlsattacker.core.workflow.action.StarttlsMessageFactory;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;

public class ServerGreetingMessagePreparator extends EmailProtocolMessagePreparator<ServerGreetingMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final ServerGreetingMessage msg;

    public ServerGreetingMessagePreparator(Chooser chooser, ServerGreetingMessage message) {
        super(chooser, message);
        this.msg = message;
    }

    @Override
    protected byte[] convertData() {
        StarttlsMessageFactory factory = new StarttlsMessageFactory(chooser.getConfig());
        StarttlsType type = chooser.getConfig().getStarttlsType();
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        try {
            switch (type) {
                case IMAP: {
                    boolean isPreauth = chooser.getConfig().getIMAPPreAuth();
                    boolean isCapaInGreeting = chooser.getConfig().getIMAPCapaInGreeting();
                    if (isPreauth)
                        stream.write("* PREAUTH".getBytes(StandardCharsets.UTF_8));
                    else {
                        stream.write("* OK".getBytes(StandardCharsets.UTF_8));
                        if (isCapaInGreeting) {
                            List<ServerCapability> capabilities = chooser.getConfig().getDefaultServerCapabilities();
                            if (capabilities != null && !capabilities.isEmpty()) {
                                stream.write(" [".getBytes(StandardCharsets.UTF_8));
                                for (ServerCapability capa : capabilities) {
                                    String line = " " + capa.getServerCapability();
                                    stream.write((line.getBytes(StandardCharsets.UTF_8)));
                                }
                                stream.write(" ]".getBytes(StandardCharsets.UTF_8));
                            }
                        }
                    }
                    break;
                }
                case POP3:
                    stream.write(factory.createCommand(StarttlsMessageFactory.CommandType.S_CONNECTED).getBytes(
                            StandardCharsets.UTF_8));
                    break;
                case SMTP:
                    stream.write(factory.createCommand(StarttlsMessageFactory.CommandType.S_CONNECTED).getBytes(
                            StandardCharsets.UTF_8));
                    break;
            }
        } catch (IOException ex) {
            throw new PreparationException("Could not prepare ServerGreetingMessage.", ex);
        }
        return stream.toByteArray();
    }
}
