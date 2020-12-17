/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2020 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.protocol.message.EmailProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.EmailProtocolMessageParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.EmailProtocolMessagePreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.EmailProtocolMessageSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;

public abstract class EmailProtocolMessageHandler<Message extends EmailProtocolMessage> extends
        ProtocolMessageHandler<Message> {
    /**
     * @param tlsContext
     *            The Context which should be Adjusted with this Handler
     */
    public EmailProtocolMessageHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public abstract EmailProtocolMessageParser getParser(byte[] message, int pointer);

    @Override
    public abstract EmailProtocolMessagePreparator getPreparator(Message message);

    @Override
    public abstract EmailProtocolMessageSerializer getSerializer(Message message);

    @Override
    public void adjustTLSContext(Message message) {

    }
}
