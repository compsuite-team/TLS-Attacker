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

import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.ServerGreetingMessage;
import de.rub.nds.tlsattacker.core.protocol.serializer.EmailProtocolMessageSerializer;

public class ServerGreetingMessageSerializer extends EmailProtocolMessageSerializer<ServerGreetingMessage> {
    /**
     * Constructor for the ServerGreetingSerializer
     *
     * @param message
     *            Message that should be serialized
     * @param version
     */
    public ServerGreetingMessageSerializer(ServerGreetingMessage message, ProtocolVersion version) {
        super(message, version);
    }
}
