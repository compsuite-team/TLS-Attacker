/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.serializer;

import de.rub.nds.tlsattacker.core.protocol.message.EndOfEarlyDataMessage;

/** RFC draft-ietf-tls-tls13-21 */
public class EndOfEarlyDataSerializer extends HandshakeMessageSerializer<EndOfEarlyDataMessage> {

    public EndOfEarlyDataSerializer(EndOfEarlyDataMessage message) {
        super(message);
    }

    @Override
    public byte[] serializeHandshakeMessageContent() {
        return getAlreadySerialized(); // empty message
    }
}
