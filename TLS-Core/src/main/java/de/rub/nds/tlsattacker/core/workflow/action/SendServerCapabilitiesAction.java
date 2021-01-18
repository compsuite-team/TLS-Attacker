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
import java.nio.charset.StandardCharsets;
import java.util.List;

public class SendServerCapabilitiesAction extends SendStarttlsAsciiAction {

    private static final Logger LOGGER = LogManager.getLogger();

    public SendServerCapabilitiesAction() {
        super();
    }

    public SendServerCapabilitiesAction(Config config) {
        super(config);
    }

    public SendServerCapabilitiesAction(String encoding, Config config) {
        super(encoding, config);
    }

    // TODO: Capabilities aus Messagefactory heraus erzeugen.
    @Override
    public String initAsciiText(TlsContext tlsContext) {
        Chooser chooser = tlsContext.getChooser();
        List<ServerCapability> capabilities = chooser.getConfig().getDefaultServerCapabilities();
        StarttlsMessageFactory factory = new StarttlsMessageFactory(chooser.getConfig());
        StringBuilder builder = new StringBuilder();
        switch (getType()) {
            case IMAP: {
                builder.append("*");
                for (ServerCapability capa : capabilities) {
                    builder.append(" " + capa.getServerCapability());
                }
                builder.append("\r\n" + tlsContext.getRecentIMAPTag() + " OK");
                break;
            }
            case POP3: {
                builder.append("+OK");
                for (ServerCapability capa : capabilities) {
                    builder.append("\r\n" + capa.getServerCapability());
                }
                builder.append("\r\n.\r\n");
                break;
            }
            case SMTP: {
                builder.append("250-mail.example.org");
                for (ServerCapability capa : capabilities) {
                    if (capa != capabilities.get(capabilities.size() - 1))
                        builder.append("\r\n250-" + capa.getServerCapability());
                    else
                        builder.append("\r\n250 " + capa.getServerCapability());
                }
            }
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
        return "Sending Server Capabilities";
    }
}
