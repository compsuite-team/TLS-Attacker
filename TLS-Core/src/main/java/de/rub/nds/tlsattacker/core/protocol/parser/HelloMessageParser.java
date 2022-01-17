/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.parser;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.HelloMessage;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import java.io.InputStream;
import java.util.Arrays;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * An abstract Parser class for Hello Messages
 *
 * @param <T>
 *            Type of the HelloMessage to parse
 */
public abstract class HelloMessageParser<T extends HelloMessage> extends HandshakeMessageParser<T> {

    private static final Logger LOGGER = LogManager.getLogger();

    /**
     * Constructor for the Parser class
     *
     * @param stream
     * @param type
     *                Expected Type value for the Message
     * @param version
     *                Version of the Protocol
     * @param context
     *                A Config used in the current context
     */
    public HelloMessageParser(InputStream stream, HandshakeMessageType type, ProtocolVersion version,
        TlsContext context) {
        super(stream, type, version, context);
    }

    protected boolean hasSessionID(HelloMessage message) {
        return message.getSessionIdLength().getValue() > 0;
    }

    /**
     * Reads the next bytes as a ProtocolVersion and writes them in the message
     *
     * @param message
     *                Message to write in
     */
    protected void parseProtocolVersion(HelloMessage message) {
        message.setProtocolVersion(parseByteArrayField(HandshakeByteLength.VERSION));
        LOGGER.debug("ProtocolVersion:" + ArrayConverter.bytesToHexString(message.getProtocolVersion().getValue()));
    }

    /**
     * Reads the next bytes as a the Random and writes them in the message
     *
     * @param message
     *                Message to write in
     */
    protected void parseRandom(HelloMessage message) {
        message.setRandom(parseByteArrayField(HandshakeByteLength.RANDOM));
        LOGGER.debug("Random:" + ArrayConverter.bytesToHexString(message.getRandom().getValue()));
        message.setUnixTime(Arrays.copyOf(message.getRandom().getValue(), HandshakeByteLength.UNIX_TIME));
        LOGGER.debug("UnixTime:" + ArrayConverter.bytesToHexString(message.getUnixTime().getValue()));
    }

    /**
     * Reads the next bytes as the SessionID length and writes them in the message
     *
     * @param message
     *                Message to write in
     */
    protected void parseSessionIDLength(HelloMessage message) {
        message.setSessionIdLength(parseIntField(HandshakeByteLength.SESSION_ID_LENGTH));
        LOGGER.debug("SessionIDLength:" + message.getSessionIdLength().getValue());
    }

    /**
     * Reads the next bytes as the SessionID and writes them in the message
     *
     * @param message
     *                Message to write in
     */
    protected void parseSessionID(HelloMessage message) {
        message.setSessionId(parseByteArrayField(message.getSessionIdLength().getOriginalValue()));
        LOGGER.debug("SessionID:" + ArrayConverter.bytesToHexString(message.getSessionId().getValue()));
    }

}
