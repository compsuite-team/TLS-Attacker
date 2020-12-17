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

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.ServerCapaMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.EmailProtocolMessageParser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ServerCapaMessageParser extends EmailProtocolMessageParser<ServerCapaMessage> {

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
    public ServerCapaMessageParser(int pointer, byte[] array, ProtocolVersion version, Config config) {
        super(pointer, array, version, config);
    }

    @Override
    protected ServerCapaMessage createEmailProtocolMessage() {
        return new ServerCapaMessage(getConfig());
    }
}
