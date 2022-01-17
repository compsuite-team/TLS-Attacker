/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.protocol.message.RSAServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import java.math.BigInteger;

public class RSAServerKeyExchangeHandler extends ServerKeyExchangeHandler<RSAServerKeyExchangeMessage> {

    public RSAServerKeyExchangeHandler(TlsContext context) {
        super(context);
    }

    @Override
    public void adjustContext(RSAServerKeyExchangeMessage message) {
        context.setServerRSAModulus(new BigInteger(1, message.getModulus().getValue()));
        context.setServerRSAPublicKey(new BigInteger(1, message.getPublicKey().getValue()));
        if (message.getComputations() != null && message.getComputations().getPrivateKey() != null) {
            context.setServerRSAPrivateKey(message.getComputations().getPrivateKey().getValue());
        }
    }

}
