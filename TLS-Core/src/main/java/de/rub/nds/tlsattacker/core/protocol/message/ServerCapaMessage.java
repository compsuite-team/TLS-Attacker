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
import de.rub.nds.tlsattacker.core.protocol.handler.ServerCapaMessageHandler;
import de.rub.nds.tlsattacker.core.protocol.message.EmailProtocolMessage;
import de.rub.nds.tlsattacker.core.state.TlsContext;

import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement
public class ServerCapaMessage extends EmailProtocolMessage {

    // @XmlTransient
    // private StarttlsType starttlsType;

    public ServerCapaMessage(Config tlsConfig) {
        super();
        this.protocolMessageType = ProtocolMessageType.UNKNOWN;
        // this.starttlsType = tlsConfig.getStarttlsType();
    }

    public ServerCapaMessage() {
        super();
    }

    @Override
    public String toString() {
        /*
         * StringBuilder sb = new StringBuilder(); switch (starttlsType) { case
         * IMAP: { sb.append("* OK");
         *//**
         * for(ServerCapability capa : capabilities) { sb.append }
         */
        /*
         * } case POP3: { } case SMTP: { } } return sb.toString();
         */
        return null;
    }

    @Override
    public String toCompactString() {
        return "Server Capabilities";
    }

    @Override
    public ServerCapaMessageHandler getHandler(TlsContext context) {
        return new ServerCapaMessageHandler(context);
    }
}
