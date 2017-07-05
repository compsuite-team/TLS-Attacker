/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.modifiablevariable.util.RandomHelper;
import de.rub.nds.tlsattacker.core.constants.HeartbeatMessageType;
import de.rub.nds.tlsattacker.core.protocol.message.HeartbeatMessage;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class HeartbeatMessagePreparatorTest {
    private static final Logger LOGGER = LogManager.getLogger(HeartbeatMessagePreparatorTest.class);

    private TlsContext context;
    private HeartbeatMessage message;
    private HeartbeatMessagePreparator preparator;

    @Before
    public void setUp() {
        this.context = new TlsContext();
        this.message = new HeartbeatMessage();
        this.preparator = new HeartbeatMessagePreparator(context, message);
        RandomHelper.getRandom().setSeed(0);
    }

    /**
     * Test of prepareProtocolMessageContents method, of class
     * HeartbeatMessagePreparator.
     */
    @Test
    public void testPrepare() {
        context.getConfig().setHeartbeatPayloadLength(11);
        context.getConfig().setHeartbeatMaxPaddingLength(11);
        context.getConfig().setHeartbeatMinPaddingLength(5);
        preparator.prepare();
        assertTrue(HeartbeatMessageType.HEARTBEAT_REQUEST.getValue() == message.getHeartbeatMessageType().getValue());
        LOGGER.info("padding: " + ArrayConverter.bytesToHexString(message.getPadding().getValue()));
        LOGGER.info("payload: " + ArrayConverter.bytesToHexString(message.getPayload().getValue()));

        assertArrayEquals(ArrayConverter.hexStringToByteArray("F6C92DA33AF01D4FB770"), message.getPadding().getValue());
        assertArrayEquals(ArrayConverter.hexStringToByteArray("60B420BB3851D9D47ACB93"), message.getPayload()
                .getValue());
        assertTrue(11 == message.getPayloadLength().getValue());
    }

}
