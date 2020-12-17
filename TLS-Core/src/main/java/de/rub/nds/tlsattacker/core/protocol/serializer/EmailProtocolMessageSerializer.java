/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2020 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.serializer;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.EmailProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.serializer.ProtocolMessageSerializer;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class EmailProtocolMessageSerializer<Message extends EmailProtocolMessage> extends
        ProtocolMessageSerializer<Message> {
    private static final Logger LOGGER = LogManager.getLogger();

    private final Message msg;

    /**
     * Constructor for the ServerGreetingSerializer
     *
     * @param message
     *            Message that should be serialized
     * @param version
     *            Version of the Protocol
     */
    public EmailProtocolMessageSerializer(Message message, ProtocolVersion version) {
        super(message, version);
        this.msg = message;
    }

    @Override
    public byte[] serializeProtocolMessageContent() {
        LOGGER.debug("Serializing ServerCapaMessage");
        writeData(msg);
        return getAlreadySerialized();
    }

    /**
     * Writes the data of the ServerCapaMessage into the final byte[]
     */
    protected void writeData(Message msg) {
        appendBytes(msg.getMessage().getValue());
        LOGGER.debug("Message: " + ArrayConverter.bytesToHexString(msg.getMessage().getValue()));
    }

}
