/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.serializer;

import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.ECDHClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.ECDHClientKeyExchangeParserTest;
import java.util.Collection;
import static org.junit.Assert.*;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(Parameterized.class)
public class ECDHClientKeyExchangeSerializerTest {

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return ECDHClientKeyExchangeParserTest.generateData();
    }

    private byte[] message;
    private int serializedKeyLength;
    private byte[] serializedKey;
    private ProtocolVersion version;

    public ECDHClientKeyExchangeSerializerTest(byte[] message, int serializedKeyLength, byte[] serializedKey,
        ProtocolVersion version) {
        this.message = message;
        this.serializedKeyLength = serializedKeyLength;
        this.serializedKey = serializedKey;
        this.version = version;
    }

    /**
     * Test of serializeProtocolMessageContent method, of class ECDHClientKeyExchangeSerializer.
     */
    @Test
    public void testserializeProtocolMessageContent() {
        ECDHClientKeyExchangeMessage msg = new ECDHClientKeyExchangeMessage();
        msg.setPublicKey(serializedKey);
        msg.setPublicKeyLength(serializedKeyLength);
        ECDHClientKeyExchangeSerializer serializer = new ECDHClientKeyExchangeSerializer(msg, version);
        assertArrayEquals(this.message, serializer.serializeProtocolMessageContent());
    }

}
