/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ServerCertificateTypeExtensionMessage;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.io.InputStream;

public class ServerCertificateTypeExtensionParser
        extends ExtensionParser<ServerCertificateTypeExtensionMessage> {

    public ServerCertificateTypeExtensionParser(InputStream stream, TlsContext tlsContext) {
        super(stream, tlsContext);
    }

    @Override
    public void parse(ServerCertificateTypeExtensionMessage msg) {
        if (getTlsContext().getTalkingConnectionEndType() == ConnectionEndType.CLIENT) {
            msg.setCertificateTypesLength(
                    parseIntField(ExtensionByteLength.CERTIFICATE_TYPE_TYPE_LENGTH));
            msg.setCertificateTypes(
                    parseByteArrayField(msg.getCertificateTypesLength().getValue()));
        } else {
            msg.setCertificateTypes(
                    parseByteArrayField(ExtensionByteLength.CERTIFICATE_TYPE_TYPE_LENGTH));
        }
    }
}
