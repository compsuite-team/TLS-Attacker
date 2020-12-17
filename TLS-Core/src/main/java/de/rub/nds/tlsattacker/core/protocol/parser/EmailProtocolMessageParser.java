/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2020 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.parser;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.EmailProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.ProtocolMessageParser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class EmailProtocolMessageParser<Message extends EmailProtocolMessage> extends
        ProtocolMessageParser<Message> {

    private static final Logger LOGGER = LogManager.getLogger();

    /**
     * Constructor for the Parser class
     *
     * @param pointer
     *            Position in the array where the ProtocolMessageParser is
     *            supposed to start parsing
     * @param array
     *            The byte[] which the ProtocolMessageParser is supposed to
     *            parse
     * @param version
     *            Version of the Protocol
     * @param config
     *            A Config used in the current context
     */
    public EmailProtocolMessageParser(int pointer, byte[] array, ProtocolVersion version, Config config) {
        super(pointer, array, version, config);
    }

    protected abstract Message createEmailProtocolMessage();

    @Override
    protected Message parseMessageContent() {
        LOGGER.debug("parsing ServerCapabilities");
        Message msg = createEmailProtocolMessage();
        parseMessage(msg);
        return msg;
    }

    /**
     * Reads the next bytes as the Data and writes them in the message
     *
     * @param msg
     *            Message to write in
     */
    protected void parseMessage(Message msg) {
        msg.setMessage(parseByteArrayField(getBytesLeft()));
        LOGGER.debug("Server Message: " + ArrayConverter.bytesToHexString(msg.getMessage().getValue()));
    }
}
