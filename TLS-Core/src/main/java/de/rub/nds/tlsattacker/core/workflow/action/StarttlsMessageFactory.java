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
import de.rub.nds.tlsattacker.core.config.TLSDelegateConfig;
import de.rub.nds.tlsattacker.core.constants.ServerCapability;
import de.rub.nds.tlsattacker.core.constants.StarttlsType;
import de.rub.nds.tlsattacker.core.state.TlsContext;

import java.util.List;

public class StarttlsMessageFactory {

    private final Config config;

    private final StarttlsType starttlsType;

    public StarttlsMessageFactory(Config config) {
        this.config = config;
        this.starttlsType = config.getStarttlsType();
    }

    public String createCommand(CommandType commandType) {
        return createCommand(commandType, "");
    }

    public String createCommand(CommandType commandType, String tag) {
        // TODO: How to handle empty capabilities?
        String IMAPTag = tag;
        if (!"".equals(IMAPTag))
            IMAPTag = IMAPTag + " ";
        switch (starttlsType) {
            case IMAP: {
                StringBuilder builder = new StringBuilder();
                for (ServerCapability capa : config.getDefaultServerCapabilities()) {
                    builder.append("\r\n" + capa.getServerCapability());
                }
                switch (commandType) {
                    case S_CONNECTED:
                        return "* OK [" + builder.toString() + "] Service Ready\r\n";
                    case C_CAPA:
                        return IMAPTag + "CAPABILITY";
                    case S_CAPA:
                        return "* " + builder.toString() + "\r\n" + IMAPTag + " OK";
                    case C_STARTTLS:
                        return IMAPTag + "STARTTLS";
                    case S_STARTTLS:
                        return IMAPTag + "OK let's talk TLS";
                    case S_OK:
                        return IMAPTag + "OK";
                    case C_NOOP:
                        return IMAPTag + "NOOP";
                    case C_QUIT:
                        return IMAPTag + "LOGOUT";
                    case S_BYE:
                        return "* BYE\r\n" + IMAPTag + "OK";
                }
            }
            case POP3: {
                switch (commandType) {
                    case S_CONNECTED:
                        return "+OK Bonjour from POP3";
                    case C_CAPA:
                        return "CAPA";
                    case S_CAPA:
                        StringBuilder builder = new StringBuilder();
                        builder.append("+OK");
                        for (ServerCapability capa : config.getDefaultServerCapabilities()) {
                            builder.append("\r\n" + capa.getServerCapability());
                        }
                        builder.append("\r\n.");
                        return builder.toString();
                    case C_STARTTLS:
                        return "STLS";
                    case S_STARTTLS:
                        return "+OK Begin TLS negotiation";
                    case C_QUIT:
                        return "QUIT";
                    case S_OK:
                    case S_BYE:
                        return "+OK";
                }

            }
            case SMTP: {
                switch (commandType) {
                    case S_CONNECTED:
                        return "220 mail.example.com Hello from SMTP";
                    case C_CAPA:
                        return "EHLO";
                    case S_CAPA:
                        List<ServerCapability> capabilities = config.getDefaultServerCapabilities();
                        StringBuilder builder = new StringBuilder();
                        builder.append("250-mail.example.org");
                        if (!capabilities.isEmpty()) {
                            for (int i = 0; i < capabilities.size() - 1; i++) {
                                builder.append("250-" + capabilities.get(i));
                            }
                            builder.append("250 " + capabilities.get(capabilities.size() - 1));
                        }
                        return builder.toString();
                    case C_STARTTLS:
                        return "STARTTLS";
                    case S_STARTTLS:
                        return "220 Go ahead";
                    case C_NOOP:
                        return "NOOP";
                    case S_OK:
                        return "250 OK";
                    case C_QUIT:
                        return "QUIT";
                    case S_BYE:
                        return "221 OK";
                }

            }
        }
        return "";
    }

    public enum CommandType {
        S_CONNECTED,
        C_CAPA,
        S_CAPA,
        C_STARTTLS,
        S_STARTTLS,
        C_NOOP,
        S_OK,
        C_QUIT,
        S_BYE
    }
}
