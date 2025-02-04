/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloDoneMessage;
import org.junit.jupiter.api.Test;

public class ServerHelloDoneHandlerTest
        extends AbstractProtocolMessageHandlerTest<ServerHelloDoneMessage, ServerHelloDoneHandler> {

    public ServerHelloDoneHandlerTest() {
        super(ServerHelloDoneMessage::new, ServerHelloDoneHandler::new);
    }

    /** Test of adjustContext method, of class ServerHelloDoneHandler. */
    @Test
    @Override
    public void testadjustContext() {
        ServerHelloDoneMessage message = new ServerHelloDoneMessage();
        handler.adjustContext(message);
        // TODO make sure nothing changed
    }
}
