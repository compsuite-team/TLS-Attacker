/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.protocol.message.CertificateStatusMessage;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;

public class CertificateStatusHandler extends HandshakeMessageHandler<CertificateStatusMessage> {
    public CertificateStatusHandler(TlsContext context) {
        super(context);
    }

    @Override
    public void adjustContext(CertificateStatusMessage message) {

    }
}
