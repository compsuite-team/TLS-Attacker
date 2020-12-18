/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2020 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.message;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.protocol.handler.ServerGreetingMessageHandler;
import de.rub.nds.tlsattacker.core.protocol.message.EmailProtocolMessage;
import de.rub.nds.tlsattacker.core.state.TlsContext;

import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement
public class ServerGreetingMessage extends EmailProtocolMessage {

    public ServerGreetingMessage(Config tlsConfig) {
        super();
        this.protocolMessageType = ProtocolMessageType.UNKNOWN;
    }

    public ServerGreetingMessage() {
        super();
    }

    @Override
    public String toCompactString() {
        return "ServerGreetingMessage";
    }

    @Override
    public ServerGreetingMessageHandler getHandler(TlsContext context) {
        return new ServerGreetingMessageHandler(context);
    }
}
