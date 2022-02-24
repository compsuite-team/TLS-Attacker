/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.message.extension;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.SignedCertificateTimestampExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.SignedCertificateTimestampExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.SignedCertificateTimestampExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.SignedCertificateTimestampExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.io.InputStream;
import javax.xml.bind.annotation.XmlRootElement;

/**
 * This extension is defined in RFC6962
 */
@XmlRootElement(name = "SignedCertificateTimestampExtension")
public class SignedCertificateTimestampExtensionMessage
    extends ExtensionMessage<SignedCertificateTimestampExtensionMessage> {

    @ModifiableVariableProperty
    private ModifiableByteArray singedTimestamp;

    /**
     * Constructor
     */
    public SignedCertificateTimestampExtensionMessage() {
        super(ExtensionType.SIGNED_CERTIFICATE_TIMESTAMP);
    }

    /**
     * @return the raw signedTimestamp
     */
    public ModifiableByteArray getSignedTimestamp() {
        return singedTimestamp;
    }

    /**
     * @param singedTimestamp
     *                        - Timestamp as ModifiableByteArray
     */
    public void setSignedTimestamp(ModifiableByteArray singedTimestamp) {
        this.singedTimestamp = singedTimestamp;
    }

    /**
     * @param singedTimestamp
     *                        - Timestamp as byte array
     */
    public void setSignedTimestamp(byte[] singedTimestamp) {
        this.singedTimestamp = ModifiableVariableFactory.safelySetValue(this.singedTimestamp, singedTimestamp);
    }

    @Override
    public SignedCertificateTimestampExtensionParser getParser(TlsContext tlsContext, InputStream stream) {
        return new SignedCertificateTimestampExtensionParser(stream);
    }

    @Override
    public SignedCertificateTimestampExtensionPreparator getPreparator(TlsContext tlsContext) {
        return new SignedCertificateTimestampExtensionPreparator(tlsContext.getChooser(), this,
            getSerializer(tlsContext));
    }

    @Override
    public SignedCertificateTimestampExtensionSerializer getSerializer(TlsContext tlsContext) {
        return new SignedCertificateTimestampExtensionSerializer(this);
    }

    @Override
    public SignedCertificateTimestampExtensionHandler getHandler(TlsContext tlsContext) {
        return new SignedCertificateTimestampExtensionHandler(tlsContext);
    }
}
