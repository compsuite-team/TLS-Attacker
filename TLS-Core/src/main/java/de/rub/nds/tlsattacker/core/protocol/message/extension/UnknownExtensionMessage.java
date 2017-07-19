/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.message.extension;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.UnknownExtensionHandler;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.modifiablevariable.util.ByteArrayAdapter;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class UnknownExtensionMessage extends ExtensionMessage {

    private byte[] typeConfig;
    private int lengthConfig;
    private byte[] dataConfig;

    @ModifiableVariableProperty
    private ModifiableByteArray extensionData;

    public UnknownExtensionMessage() {
        super(ExtensionType.UNKNOWN);
    }

    public int getLengthConfig() {
        return lengthConfig;
    }

    public void setLengthConfig(int lengthConfig) {
        this.lengthConfig = lengthConfig;
    }

    public byte[] getDataConfig() {
        return dataConfig;
    }

    @XmlJavaTypeAdapter(ByteArrayAdapter.class)
    public void setDataConfig(byte[] dataConfig) {
        this.dataConfig = dataConfig;
    }

    public byte[] getTypeConfig() {
        return typeConfig;
    }

    @XmlJavaTypeAdapter(ByteArrayAdapter.class)
    public void setTypeConfig(byte[] typeConfig) {
        this.typeConfig = typeConfig;
    }

    public ModifiableByteArray getExtensionData() {
        return extensionData;
    }

    public void setExtensionData(ModifiableByteArray extensionData) {
        this.extensionData = extensionData;
    }

    public void setExtensionData(byte[] extensionData) {
        this.extensionData = ModifiableVariableFactory.safelySetValue(this.extensionData, extensionData);
    }

    @Override
    public String toString() {
        return "UnknownExtensionMessage{ extensionData="
                + ArrayConverter.bytesToHexString(getExtensionType().getValue(), false) + " extensionLength="
                + getExtensionLength().getValue() + " extensionData="
                + ArrayConverter.bytesToHexString(extensionData.getValue(), false) + '}';
    }

    @Override
    public UnknownExtensionHandler getHandler(TlsContext context) {
        return new UnknownExtensionHandler(context);
    }

}
