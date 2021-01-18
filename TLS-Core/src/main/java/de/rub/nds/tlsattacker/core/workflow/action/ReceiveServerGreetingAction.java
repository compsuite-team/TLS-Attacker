/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2020 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ServerCapability;
import de.rub.nds.tlsattacker.core.constants.StarttlsType;
import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.IOException;
import java.util.LinkedList;
import java.util.List;

public class ReceiveServerGreetingAction extends ReceiveStarttlsAsciiAction {

    private static final Logger LOGGER = LogManager.getLogger();

    public ReceiveServerGreetingAction() {
        super();
    }

    public ReceiveServerGreetingAction(Config config) {
        super(config);
    }

    public ReceiveServerGreetingAction(String asciiText, String encoding, Config config) {
        super(asciiText, encoding, config);
    }

    public ReceiveServerGreetingAction(String encoding, Config config) {
        super(encoding, config);
    }

    @Override
    public void handleText(TlsContext tlsContext) {
        String[] parts = getAsciiText().split(" ");
        // TODO: Wird überprüfung von SMTP und POP3 Greeting benötigt?
        if (getType() == StarttlsType.IMAP) { // TOOO: Wird Preauth im
            // Context benötigt? if
            // ("PREAUTH".equals(parts[1]))
            tlsContext.setIsPreauth(true);
            if (parts.length >= 2 && parts[2] != null && parts[2].startsWith("[")) {
                tlsContext.setCapaInGreeting(true);
                List<ServerCapability> capabilities = new LinkedList<ServerCapability>();
                for (int i = 2; i < parts.length; i++) {
                    String capability = parts[i];
                    if (capability.startsWith("["))
                        capability = capability.substring(1);
                    if (capability.endsWith("]"))
                        capability = capability.substring(0, capability.length() - 1);
                    ServerCapability capa = ServerCapability.getCapabilityFromString(getType(), capability);
                    if (capa != null)
                        capabilities.add(capa);
                }
                tlsContext.setServerCapabilities(capabilities);
            }
        }
    }

    @Override
    public void reset() {
        setExecuted(null);
    }

    @Override
    public boolean executedAsPlanned() {
        return isExecuted();
    }

    @Override
    public String getActionInfo() {
        return "Receiving Server Greeting...";
    }

}
