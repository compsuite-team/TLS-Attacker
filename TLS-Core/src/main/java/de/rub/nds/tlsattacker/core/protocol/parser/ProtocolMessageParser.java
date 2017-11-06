/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.parser;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.ProtocolMessage;

/**
 * An abstract Parser class for ProtocolMessages
 *
 * @author Robert Merget - robert.merget@rub.de
 * @param <T>
 *            Type of the HandshakeMessages to parse
 */
public abstract class ProtocolMessageParser<T extends ProtocolMessage> extends Parser<T> {

    private final ProtocolVersion version;

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
     *
     */
    public ProtocolMessageParser(int pointer, byte[] array, ProtocolVersion version) {
        super(pointer, array);
        this.version = version;
    }

    @Override
    public final T parse() {
        T msg = parseMessageContent();
        parseCompleteResultingMessage(msg);
        return msg;
    }

    protected abstract T parseMessageContent();

    /**
     * Reads the next bytes as the CompleteResultingMessage and writes them in
     * the message
     *
     * @param msg
     *            Message to write in
     */
    private void parseCompleteResultingMessage(ProtocolMessage msg) {
        msg.setCompleteResultingMessage(getAlreadyParsed());
        LOGGER.debug("CompleteResultMessage: "
                + ArrayConverter.bytesToHexString(msg.getCompleteResultingMessage().getValue()));
    }

    protected ProtocolVersion getVersion() {
        return version;
    }
}
