/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.config.delegate;

import com.beust.jcommander.JCommander;
import de.rub.nds.tlsattacker.core.config.TlsConfig;
import org.apache.commons.lang3.builder.EqualsBuilder;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.Test;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class ClientAuthenticationDelegateTest {

    private ClientAuthenticationDelegate delegate;
    private JCommander jcommander;
    private String[] args;

    @Before
    public void setUp() {
        delegate = new ClientAuthenticationDelegate();
        jcommander = new JCommander(delegate);
    }

    /**
     * Test of isClientAuthentication method, of class
     * ClientAuthenticationDelegate.
     */
    @Test
    public void testIsClientAuthentication() {
        args = new String[1];
        args[0] = "-client_authentication";
        assertTrue(delegate.isClientAuthentication() == null);
        jcommander.parse(args);
        assertTrue(delegate.isClientAuthentication());
    }

    /**
     * Test of setClientAuthentication method, of class
     * ClientAuthenticationDelegate.
     */
    @Test
    public void testSetClientAuthentication() {
        assertTrue(delegate.isClientAuthentication() == null);
        delegate.setClientAuthentication(true);
        assertTrue(delegate.isClientAuthentication());
    }

    /**
     * Test of applyDelegate method, of class ClientAuthenticationDelegate.
     */
    @Test
    public void testApplyDelegate() {
        TlsConfig config = TlsConfig.createConfig();
        config.setClientAuthentication(false);
        args = new String[1];
        args[0] = "-client_authentication";
        jcommander.parse(args);
        delegate.applyDelegate(config);
        assertTrue(config.isClientAuthentication());

    }

    @Test
    public void testNothingSetNothingChanges() {
        TlsConfig config = TlsConfig.createConfig();
        TlsConfig config2 = TlsConfig.createConfig();
        delegate.applyDelegate(config);
        assertTrue(EqualsBuilder.reflectionEquals(config, config2, "keyStore", "ourCertificate"));// little
        // ugly
    }

}
