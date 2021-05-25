/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2020 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.workflow.action.starttls;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.StarttlsType;
import de.rub.nds.tlsattacker.core.starttls.StarttlsProtocolFactory;
import de.rub.nds.tlsattacker.core.starttls.StarttlsProtocolHandler;
import de.rub.nds.tlsattacker.core.workflow.action.AsciiAction;

public abstract class StarttlsAsciiAction extends AsciiAction {

    private final Config config;

    public StarttlsAsciiAction() {
        super();
        config = null;
    }

    public StarttlsAsciiAction(Config config) {
        super();
        this.config = config;
    }

    public StarttlsAsciiAction(String asciiText, String encoding, Config config) {
        super(asciiText, encoding);
        this.config = config;
    }

    public StarttlsAsciiAction(String encoding, Config config) {
        super(encoding);
        this.config = config;
    }

    /**
     *
     * @return the Starttls Type
     */
    public StarttlsType getType() {
        if (config == null)
            return StarttlsType.NONE;
        return config.getStarttlsType();
    }

    public StarttlsProtocolHandler getHandler() {
        return StarttlsProtocolFactory.getProtocol(getType());
    }

    public Config getConfig() {
        return config;
    }

    public abstract String getActionInfo();
}
