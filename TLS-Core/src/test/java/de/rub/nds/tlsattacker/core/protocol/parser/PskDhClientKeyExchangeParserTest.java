/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.parser;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.PskDhClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.io.ByteArrayInputStream;
import java.nio.charset.Charset;
import java.util.Arrays;
import java.util.Collection;
import static org.junit.Assert.*;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(Parameterized.class)
public class PskDhClientKeyExchangeParserTest {

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return Arrays.asList(new Object[][] { { ArrayConverter.hexStringToByteArray(
            "000f436c69656e745f6964656e74697479008032d08c13c3c7ef291e4bc7854eed91ddef2737260c09573aa8def5ce79e964a5598797470501ee6ff8be72cd8c3bbaf46ab55b77851029db3cfb38a12040a15bc8512dba290d9cae345ecf24f347e1c80c65b230e265e13c8a571e0842539536d062a6141de09017d27ac2d64c0d29cbaa19d5e55c3c6c5035c87788ac776177"),
            15, ("Client_identity".getBytes(Charset.forName("UTF-8"))), ProtocolVersion.TLS12 } });
    }

    private byte[] message;

    private int serializedPskIdentityLength;
    private byte[] serializedPskIdentity;
    private ProtocolVersion version;
    private final Config config = Config.createConfig();

    public PskDhClientKeyExchangeParserTest(byte[] message, int serializedPskIdentityLength,
        byte[] serializedPskIdentity, ProtocolVersion version) {
        this.message = message;
        this.serializedPskIdentityLength = serializedPskIdentityLength;
        this.serializedPskIdentity = serializedPskIdentity;
        this.version = version;
    }

    /**
     * Test of parse method, of class PskDhClientKeyExchangeParser.
     */
    @Test
    public void testParse() {
        PskDhClientKeyExchangeParser parser =
            new PskDhClientKeyExchangeParser(new ByteArrayInputStream(message), version, new TlsContext(config));
        PskDhClientKeyExchangeMessage msg = new PskDhClientKeyExchangeMessage();
        parser.parse(msg);
        assertTrue(serializedPskIdentityLength == msg.getIdentityLength().getValue());
        assertArrayEquals(serializedPskIdentity, msg.getIdentity().getValue());
    }

}
