/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.config.delegate;

import com.beust.jcommander.Parameter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.starttls.ServerCapability;
import de.rub.nds.tlsattacker.core.constants.StarttlsType;
import de.rub.nds.tlsattacker.core.exceptions.ConfigurationException;
import de.rub.nds.tlsattacker.core.starttls.StarttlsProtocolFactory;

public class StarttlsDelegate extends Delegate {

    @Parameter(names = "-starttls", required = false, description = "Starttls protocol")
    private StarttlsType starttlsType = StarttlsType.NONE;

    // TODO: Define default Username & Password
    @Parameter(names = "-plainUser", required = false,
        description = "Username for testing if server accepts plain logins.")
    private String plainUser = "admin";

    @Parameter(names = "-plainPwd", required = false,
        description = "Password for testing if the server accepts plain logins.")
    private String plainPwd = "pass";

    public StarttlsDelegate() {

    }

    public StarttlsType getStarttlsType() {
        return starttlsType;
    }

    public void setStarttlsType(StarttlsType starttlsType) {
        this.starttlsType = starttlsType;
    }

    public String getPlainUser() {
        return plainUser;
    }

    public void setPlainUser(String plainUser) {
        this.plainUser = plainUser;
    }

    public String getPlainPwd() {
        return plainPwd;
    }

    public void setPlainPwd(String plainPwd) {
        this.plainPwd = plainPwd;
    }

    @Override
    public void applyDelegate(Config config) throws ConfigurationException {
        config.setStarttlsType(starttlsType);
        if (starttlsType != StarttlsType.NONE) {
            config.setDefaultServerCapabilities(
                StarttlsProtocolFactory.getProtocol(starttlsType).getImplementedCapabilities());
        }
        config.setPlainUser(plainUser);
        config.setPlainPwd(plainPwd);
    }

}
