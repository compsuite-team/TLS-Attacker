/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.handler.ChangeCipherSpecHandler;
import de.rub.nds.tlsattacker.core.protocol.parser.ChangeCipherSpecParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.ChangeCipherSpecPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.ChangeCipherSpecSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;

import javax.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;

@XmlRootElement(name = "ChangeCipherSpec")
public class ChangeCipherSpecMessage extends ProtocolMessage<ChangeCipherSpecMessage> {

    @ModifiableVariableProperty
    private ModifiableByteArray ccsProtocolType;

    public ChangeCipherSpecMessage(Config tlsConfig) {
        super();
        this.protocolMessageType = ProtocolMessageType.CHANGE_CIPHER_SPEC;
    }

    public ChangeCipherSpecMessage() {
        super();
        this.protocolMessageType = ProtocolMessageType.CHANGE_CIPHER_SPEC;
    }

    public ModifiableByteArray getCcsProtocolType() {
        return ccsProtocolType;
    }

    public void setCcsProtocolType(ModifiableByteArray ccsProtocolType) {
        this.ccsProtocolType = ccsProtocolType;
    }

    public void setCcsProtocolType(byte[] value) {
        this.ccsProtocolType = ModifiableVariableFactory.safelySetValue(ccsProtocolType, value);
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("ChangeCipherSpecMessage:");
        sb.append("\n  CCS ProtocolType: ");
        if (ccsProtocolType != null && ccsProtocolType.getValue() != null) {
            sb.append(ArrayConverter.bytesToHexString(ccsProtocolType.getValue()));
        } else {
            sb.append("null");
        }
        return sb.toString();
    }

    @Override
    public String toShortString() {
        return "CCS";
    }

    @Override
    public String toCompactString() {
        return "CHANGE_CIPHER_SPEC";
    }

    @Override
    public ChangeCipherSpecHandler getHandler(TlsContext context) {
        return new ChangeCipherSpecHandler(context);
    }

    @Override
    public ChangeCipherSpecParser getParser(TlsContext tlsContext, InputStream stream) {
        return new ChangeCipherSpecParser(stream, tlsContext.getChooser().getLastRecordVersion(),
            tlsContext.getConfig());
    }

    @Override
    public ChangeCipherSpecPreparator getPreparator(TlsContext tlsContext) {
        return new ChangeCipherSpecPreparator(tlsContext.getChooser(), this);
    }

    @Override
    public ChangeCipherSpecSerializer getSerializer(TlsContext tlsContext) {
        return new ChangeCipherSpecSerializer(this, tlsContext.getChooser().getSelectedProtocolVersion());
    }
}
