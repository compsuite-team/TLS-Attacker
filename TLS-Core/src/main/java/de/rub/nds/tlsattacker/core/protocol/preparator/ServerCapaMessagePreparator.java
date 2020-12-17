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
import de.rub.nds.tlsattacker.core.protocol.message.ServerCapaMessage;
import de.rub.nds.tlsattacker.core.protocol.preparator.EmailProtocolMessagePreparator;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;

public class ServerCapaMessagePreparator extends EmailProtocolMessagePreparator<ServerCapaMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final ServerCapaMessage msg;

    public ServerCapaMessagePreparator(Chooser chooser, ServerCapaMessage message) {
        super(chooser, message);
        this.msg = message;
    }

    @Override
    protected byte[] convertData() {
        List<ServerCapability> capabilities = chooser.getConfig().getDefaultServerCapabilities();
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        StarttlsType type = chooser.getConfig().getStarttlsType();
        if (capabilities != null && !capabilities.isEmpty()) {
            try {
                switch (type) {
                    case IMAP: {
                        stream.write("*".getBytes(StandardCharsets.UTF_8));
                        for (ServerCapability capa : capabilities) {
                            String line = "\r\n" + capa.getServerCapability();
                            stream.write(line.getBytes(StandardCharsets.UTF_8));
                        }
                        String line = chooser.getContext().getRecentIMAPTag() + "OK";
                        stream.write(line.getBytes(StandardCharsets.UTF_8));
                        break;
                    }
                    case POP3: {
                        stream.write("+OK".getBytes(StandardCharsets.UTF_8));
                        for (ServerCapability capa : capabilities) {
                            String line = "\r\n" + capa.getServerCapability();
                            stream.write(line.getBytes(StandardCharsets.UTF_8));
                        }
                        stream.write("\r\n.".getBytes(StandardCharsets.UTF_8));
                        break;
                    }
                    case SMTP: {
                        stream.write("250-mail.example.org".getBytes(StandardCharsets.UTF_8));
                        for (ServerCapability capa : capabilities) {
                            String line;
                            if (capa != capabilities.get(capabilities.size() - 1))
                                line = "\r\n250-" + capa.getServerCapability();
                            else
                                line = "\r\n250 " + capa.getServerCapability();
                            stream.write(line.getBytes(StandardCharsets.UTF_8));
                        }
                    }
                }
            } catch (IOException ex) {
                throw new PreparationException(
                        "Could not prepare ServerCapaMessage. Failed to write servers capabilities.", ex);
            }
        }
        return stream.toByteArray();
    }
}
