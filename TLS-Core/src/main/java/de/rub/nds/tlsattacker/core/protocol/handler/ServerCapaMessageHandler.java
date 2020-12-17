/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2020 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.ServerCapability;
import de.rub.nds.tlsattacker.core.constants.StarttlsType;
import de.rub.nds.tlsattacker.core.protocol.message.ServerCapaMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.ServerCapaMessageParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.ServerCapaMessagePreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.ServerCapaMessageSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.LinkedList;
import java.util.List;

public class ServerCapaMessageHandler extends EmailProtocolMessageHandler<ServerCapaMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ServerCapaMessageHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public ServerCapaMessageParser getParser(byte[] message, int pointer) {
        return new ServerCapaMessageParser(pointer, message, tlsContext.getChooser().getLastRecordVersion(),
                tlsContext.getConfig());
    }

    @Override
    public ServerCapaMessagePreparator getPreparator(ServerCapaMessage message) {
        return new ServerCapaMessagePreparator(tlsContext.getChooser(), message);
    }

    @Override
    public ServerCapaMessageSerializer getSerializer(ServerCapaMessage message) {
        return new ServerCapaMessageSerializer(message, tlsContext.getChooser().getLastRecordVersion());
    }

    @Override
    public void adjustTLSContext(ServerCapaMessage message) {
        StarttlsType type = tlsContext.getConfig().getStarttlsType();
        String readableMessage = ArrayConverter.bytesToHexString(message.getMessage());
        String[] parts = readableMessage.split(" |\\r?\\n"); // Split string on
                                                             // space and new
                                                             // Line.
        List<ServerCapability> capabilities = new LinkedList<ServerCapability>();
        // TODO: Überprüfung einbauen, ob Nachricht korrekt aufgebaut ist.
        // TODO: Rufe Methode in Enum ServerCapabilities auf, welche abhängig
        // vom StarttlsType das passend Enum zum String liefert.
        for (String str : parts) {
            ServerCapability capa = ServerCapability.getCapabilityFromString(type, str);
            if (capa != null)
                capabilities.add(capa);
        }
        tlsContext.setServerCapabilities(capabilities);
    }
}
