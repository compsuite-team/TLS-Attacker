/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.starttls;

public class ServerCapability {

    protected final String name;

    private final boolean isPlain;

    private final boolean isLoginDisabled;

    private final boolean isStarttls;

    public ServerCapability() {
        this("", false, false, false);
    }

    public ServerCapability(String name, boolean isPlain, boolean isLoginDisabled, boolean isStarttls) {
        this.name = name;
        this.isPlain = isPlain;
        this.isLoginDisabled = isLoginDisabled;
        this.isStarttls = isStarttls;
    }

    public ServerCapability(String name) {
        this(name, false, false, false);
    }

    public String getName() {
        return name;
    }

    public boolean isPlain() {
        return isPlain;
    }

    public boolean isLoginDisabled() {
        return isLoginDisabled;
    }

    public boolean isStarttls() {
        return isStarttls;
    }

}
