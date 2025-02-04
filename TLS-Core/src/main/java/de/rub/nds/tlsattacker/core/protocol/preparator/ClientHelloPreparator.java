/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.preparator;

import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;

public class ClientHelloPreparator extends CoreClientHelloPreparator<ClientHelloMessage> {

    public ClientHelloPreparator(Chooser chooser, ClientHelloMessage message) {
        super(chooser, message);
    }
}
