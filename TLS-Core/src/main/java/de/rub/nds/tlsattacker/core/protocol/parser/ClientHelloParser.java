/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.parser;

import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import java.io.InputStream;

public class ClientHelloParser extends CoreClientHelloParser<ClientHelloMessage> {

    /**
     * Constructor for the Parser class
     *
     * @param stream InputStream that contains data to parse
     * @param tlsContext Context of this connection
     */
    public ClientHelloParser(InputStream stream, TlsContext tlsContext) {
        super(stream, tlsContext);
    }
}
