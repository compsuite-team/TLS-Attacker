/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.protocol.message.CertificateStatusMessage;
import org.junit.jupiter.api.Test;

public class CertificateStatusHandlerTest
        extends AbstractProtocolMessageHandlerTest<
                CertificateStatusMessage, CertificateStatusHandler> {

    public CertificateStatusHandlerTest() {
        super(CertificateStatusMessage::new, CertificateStatusHandler::new);
    }

    @Test
    @Override
    public void testadjustContext() {
        CertificateStatusMessage message = new CertificateStatusMessage();
        handler.adjustContext(message);
        // TODO: make sure that nothing changed
    }
}
