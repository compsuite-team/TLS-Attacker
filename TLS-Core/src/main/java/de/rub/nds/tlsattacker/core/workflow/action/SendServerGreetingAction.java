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
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionOption;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.IOException;
import java.util.List;

public class SendServerGreetingAction extends SendStarttlsAsciiAction {

    private static final Logger LOGGER = LogManager.getLogger();

    public SendServerGreetingAction() {
        super();
    }

    public SendServerGreetingAction(Config config) {
        super(config);
    }

    public SendServerGreetingAction(String encoding, Config config) {
        super(encoding, config);
    }

    public String initAsciiText(TlsContext tlsContext) {
        Chooser chooser = tlsContext.getChooser();
        StarttlsMessageFactory factory = new StarttlsMessageFactory(chooser.getConfig());
        StringBuilder builder = new StringBuilder();
        switch (getType()) {
            case IMAP: {
                boolean isPreauth = chooser.getConfig().getIMAPPreAuth();
                boolean isCapaInGreeting = chooser.getConfig().getIMAPCapaInGreeting();
                if (isPreauth)
                    builder.append("* PREAUTH");
                else {
                    builder.append("* OK");
                    if (isCapaInGreeting) {
                        List<ServerCapability> capabilities = chooser.getConfig().getDefaultServerCapabilities();
                        if (capabilities != null && !capabilities.isEmpty()) {
                            builder.append(" [");
                            for (ServerCapability capa : capabilities) {
                                builder.append(" " + capa.getServerCapability());
                            }
                            builder.append(" ]");
                        }
                    }
                }
                break;
            }
            case POP3:
            case SMTP:
                builder.append(factory.createSendCommand(StarttlsMessageFactory.CommandType.S_CONNECTED));
                break;
        }
        return builder.toString();
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
        return "Sending Server Greeting:";
    }
}
