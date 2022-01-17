/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.protocol.message.SrpClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;

/**
 * Handler for SRP ClientKeyExchange messages
 *
 */
public class SrpClientKeyExchangeHandler extends ClientKeyExchangeHandler<SrpClientKeyExchangeMessage> {

    public SrpClientKeyExchangeHandler(TlsContext context) {
        super(context);
    }

    @Override
    public void adjustContext(SrpClientKeyExchangeMessage message) {
        adjustPremasterSecret(message);
        adjustMasterSecret(message);
        spawnNewSession();
    }
}
