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
import de.rub.nds.tlsattacker.core.protocol.message.ServerGreetingMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.EmailProtocolMessageParser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ServerGreetingMessageParser extends EmailProtocolMessageParser<ServerGreetingMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ServerGreetingMessageParser(int pointer, byte[] array, ProtocolVersion version, Config config) {
        super(pointer, array, version, config);
    }

    @Override
    protected ServerGreetingMessage createEmailProtocolMessage() {
        return new ServerGreetingMessage(getConfig());
    }
}
