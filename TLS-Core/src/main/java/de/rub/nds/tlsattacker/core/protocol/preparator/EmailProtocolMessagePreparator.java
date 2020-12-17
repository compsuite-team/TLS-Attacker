/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2020 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.protocol.message.EmailProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.preparator.ProtocolMessagePreparator;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class EmailProtocolMessagePreparator<Message extends EmailProtocolMessage> extends
        ProtocolMessagePreparator<Message> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final Message msg;

    public EmailProtocolMessagePreparator(Chooser chooser, Message message) {
        super(chooser, message);
        this.msg = message;
    }

    @Override
    protected void prepareProtocolMessageContents() {
        LOGGER.debug("Preparing EmailProtocolMessage:");
        byte[] data = convertData();
        prepareMessage(msg, data);
    }

    protected void prepareMessage(Message message, byte[] data) {
        msg.setMessage(data);
        LOGGER.debug("Server data: " + ArrayConverter.bytesToHexString(msg.getMessage()));
    }

    protected abstract byte[] convertData();
}
