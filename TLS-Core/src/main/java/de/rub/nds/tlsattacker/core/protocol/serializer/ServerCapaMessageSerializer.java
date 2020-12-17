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
import de.rub.nds.tlsattacker.core.protocol.message.ServerCapaMessage;
import de.rub.nds.tlsattacker.core.protocol.serializer.EmailProtocolMessageSerializer;

public class ServerCapaMessageSerializer extends EmailProtocolMessageSerializer<ServerCapaMessage> {
    /**
     * Constructor for the ServerCapaMessageSerializer
     *
     * @param message
     *            Message that should be serialized
     * @param version
     */
    public ServerCapaMessageSerializer(ServerCapaMessage message, ProtocolVersion version) {
        super(message, version);
    }
}
