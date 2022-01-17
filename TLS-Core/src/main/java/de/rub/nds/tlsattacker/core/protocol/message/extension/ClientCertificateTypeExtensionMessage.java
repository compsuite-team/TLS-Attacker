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
import de.rub.nds.modifiablevariable.bool.ModifiableBoolean;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.ClientCertificateTypeExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.ClientCertificateTypeExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.ClientCertificateTypeExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.ClientCertificateTypeExtensionSerializer;
import java.io.InputStream;
import javax.xml.bind.annotation.XmlRootElement;

/**
 * This extension is defined in RFC7250
 */
@XmlRootElement(name = "ClientCertificateTypeExtension")
public class ClientCertificateTypeExtensionMessage extends ExtensionMessage<ClientCertificateTypeExtensionMessage> {

    @ModifiableVariableProperty
    private ModifiableInteger certificateTypesLength;
    @ModifiableVariableProperty
    private ModifiableByteArray certificateTypes;
    @ModifiableVariableProperty
    private ModifiableBoolean isClientMessage;

    public ClientCertificateTypeExtensionMessage() {
        super(ExtensionType.CLIENT_CERTIFICATE_TYPE);
    }

    public ClientCertificateTypeExtensionMessage(Config config) {
        super(ExtensionType.CLIENT_CERTIFICATE_TYPE);
    }

    public ModifiableInteger getCertificateTypesLength() {
        return certificateTypesLength;
    }

    public void setCertificateTypesLength(ModifiableInteger certificateTypesLength) {
        this.certificateTypesLength = certificateTypesLength;
    }

    public void setCertificateTypesLength(int certificateTypesLength) {
        this.certificateTypesLength =
            ModifiableVariableFactory.safelySetValue(this.certificateTypesLength, certificateTypesLength);
    }

    public ModifiableByteArray getCertificateTypes() {
        return certificateTypes;
    }

    public void setCertificateTypes(ModifiableByteArray certificateTypes) {
        this.certificateTypes = certificateTypes;
    }

    public void setCertificateTypes(byte[] certificateTypes) {
        this.certificateTypes = ModifiableVariableFactory.safelySetValue(this.certificateTypes, certificateTypes);
    }

    public ModifiableBoolean getIsClientMessage() {
        return isClientMessage;
    }

    public void setIsClientMessage(ModifiableBoolean isClientMessage) {
        this.isClientMessage = isClientMessage;
    }

    public void setIsClientMessage(boolean isClientMessage) {
        this.isClientMessage = ModifiableVariableFactory.safelySetValue(this.isClientMessage, isClientMessage);
    }

    @Override
    public ClientCertificateTypeExtensionParser getParser(TlsContext context, InputStream stream) {
        return new ClientCertificateTypeExtensionParser(stream, context.getConfig());
    }

    @Override
    public ClientCertificateTypeExtensionPreparator getPreparator(TlsContext context) {
        return new ClientCertificateTypeExtensionPreparator(context.getChooser(), this, getSerializer(context));
    }

    @Override
    public ClientCertificateTypeExtensionSerializer getSerializer(TlsContext context) {
        return new ClientCertificateTypeExtensionSerializer(this);
    }

    @Override
    public ClientCertificateTypeExtensionHandler getHandler(TlsContext context) {
        return new ClientCertificateTypeExtensionHandler(context);
    }
}
