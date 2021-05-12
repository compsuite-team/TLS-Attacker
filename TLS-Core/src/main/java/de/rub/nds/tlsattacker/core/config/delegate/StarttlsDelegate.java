/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2020 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.config.delegate;

import com.beust.jcommander.Parameter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.config.converters.StarttlsTypeConverter;
import de.rub.nds.tlsattacker.core.constants.ServerCapability;
import de.rub.nds.tlsattacker.core.constants.StarttlsType;
import de.rub.nds.tlsattacker.core.exceptions.ConfigurationException;

public class StarttlsDelegate extends Delegate {

    @Parameter(names = "-starttls", required = false, description = "Starttls protocol. Choose from ftp, imap, pop3, smtp.", converter = StarttlsTypeConverter.class)
    private StarttlsType starttlsType = StarttlsType.NONE;

    // TODO: Define default Username & Password
    @Parameter(names = "-plainUser", required = false, description = "Username for testing if server accepts plain logins.")
    private String plainUser = "admin";

    @Parameter(names = "-plainPwd", required = false, description = "Password for testing if the server accepts plain logins.")
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
            // config.setServerSendsApplicationData(true);
            config.setDefaultServerCapabilities(ServerCapability.getImplemented(starttlsType));
        }
        config.setPlainUser(plainUser);
        config.setPlainPwd(plainPwd);
    }

}
