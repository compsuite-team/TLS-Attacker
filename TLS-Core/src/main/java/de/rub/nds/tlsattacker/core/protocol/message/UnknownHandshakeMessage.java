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
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.protocol.handler.UnknownHandshakeHandler;
import de.rub.nds.tlsattacker.core.protocol.parser.UnknownHandshakeParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.UnknownHandshakePreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.UnknownHandshakeSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;

import javax.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;

@XmlRootElement(name = "UnknownHandshakeMessage")
public class UnknownHandshakeMessage extends HandshakeMessage {

    private byte[] dataConfig;

    @ModifiableVariableProperty
    private ModifiableByteArray data;

    public UnknownHandshakeMessage() {
        super(HandshakeMessageType.UNKNOWN);
    }

    public UnknownHandshakeMessage(Config config) {
        super(HandshakeMessageType.UNKNOWN);
    }

    public byte[] getDataConfig() {
        return dataConfig;
    }

    public void setDataConfig(byte[] dataConfig) {
        this.dataConfig = dataConfig;
    }

    public ModifiableByteArray getData() {
        return data;
    }

    public void setData(ModifiableByteArray data) {
        this.data = data;
    }

    public void setData(byte[] data) {
        this.data = ModifiableVariableFactory.safelySetValue(this.data, data);
    }

    @Override
    public UnknownHandshakeHandler getHandler(TlsContext context) {
        return new UnknownHandshakeHandler(context);
    }

    @Override
    public UnknownHandshakeParser getParser(TlsContext tlsContext, InputStream stream) {
        return new UnknownHandshakeParser(stream, tlsContext.getChooser().getLastRecordVersion(), tlsContext);
    }

    @Override
    public UnknownHandshakePreparator getPreparator(TlsContext tlsContext) {
        return new UnknownHandshakePreparator(tlsContext.getChooser(), this);
    }

    @Override
    public UnknownHandshakeSerializer getSerializer(TlsContext tlsContext) {
        return new UnknownHandshakeSerializer(this, tlsContext.getChooser().getSelectedProtocolVersion());
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("UnknownHandshakeMessage:");
        sb.append("\n  Data: ");
        if (data != null && data.getValue() != null) {
            sb.append(ArrayConverter.bytesToHexString(data.getValue()));
        } else {
            sb.append("null");
        }
        return sb.toString();
    }

    @Override
    public String toShortString() {
        return "HS(?)";
    }

}
