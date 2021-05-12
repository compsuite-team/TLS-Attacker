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
import de.rub.nds.tlsattacker.core.constants.ServerCapability;
import de.rub.nds.tlsattacker.core.constants.StarttlsType;

import java.util.List;

public class StarttlsMessageFactory {

    private Config config;

    private StarttlsType starttlsType;

    public StarttlsMessageFactory(Config config) {
        this.config = config;
        this.starttlsType = config.getStarttlsType();
    }

    private StarttlsMessageFactory() {
    }

    public String createSendCommand(CommandType commandType) {
        return createCommand(commandType, "abc");
    }

    public String createResponseCommand(CommandType commandType) {
        return createCommand(commandType, "");
    }

    public String createCommand(CommandType commandType, String tag) {
        String IMAPTag = tag;
        if (!"".equals(IMAPTag))
            IMAPTag = IMAPTag + " ";
        switch (starttlsType) {
            case IMAP: {
                StringBuilder builder = new StringBuilder();
                for (ServerCapability capa : config.getDefaultServerCapabilities()) {
                    if (!(commandType == CommandType.S_CAPA && capa == ServerCapability.IMAP_CAPABILITY))
                        builder.append(" " + capa.getServerCapability());
                }
                switch (commandType) {
                    case S_CONNECTED:
                        return "* OK [" + builder.toString() + "] Service Ready\r\n";
                    case C_CAPA:
                        return IMAPTag + "CAPABILITY\r\n";
                    case S_CAPA:
                        return "* CAPABILITY" + builder.toString() + "\r\n" + IMAPTag + "OK caps done\r\n";
                    case C_STARTTLS:
                        return IMAPTag + "STARTTLS\r\n";
                    case S_STARTTLS:
                        return IMAPTag + "OK Begin TLS negotiation\r\n";
                    case S_OK:
                        return IMAPTag + "OK done\r\n";
                    case C_NOOP:
                        return IMAPTag + "NOOP\r\n";
                    case C_QUIT:
                        return IMAPTag + "LOGOUT\r\n";
                    case S_BYE:
                        return "* BYE\r\n" + IMAPTag + "OK done\r\n";
                }
            }
            case POP3: {
                switch (commandType) {
                    case S_CONNECTED:
                        return "+OK Bonjour from POP3\r\n";
                    case C_CAPA:
                        return "CAPA\r\n";
                    case S_CAPA:
                        StringBuilder builder = new StringBuilder();
                        builder.append("+OK");
                        for (ServerCapability capa : config.getDefaultServerCapabilities()) {
                            builder.append("\r\n" + capa.getServerCapability());
                        }
                        builder.append("\r\n.\r\n");
                        return builder.toString();
                    case C_STARTTLS:
                        return "STLS\r\n";
                    case S_STARTTLS:
                        return "+OK Begin TLS negotiation\r\n";
                    case C_QUIT:
                        return "QUIT\r\n";
                    case S_OK:
                    case S_BYE:
                        return "+OK\r\n";
                    case S_ERR:
                        return "-ERR\r\n";
                }

            }
            case SMTP: {
                switch (commandType) {
                    case S_CONNECTED:
                        return "220 mail.example.com Hello from SMTP\r\n";
                    case C_CAPA:
                        return "EHLO mail.example.com\r\n";
                    case S_CAPA:
                        List<ServerCapability> capabilities = config.getDefaultServerCapabilities();
                        StringBuilder builder = new StringBuilder();
                        builder.append("250-mail.example.org\r\n");
                        if (!capabilities.isEmpty()) {
                            for (int i = 0; i < capabilities.size() - 1; i++) {
                                builder.append("250-" + capabilities.get(i).getServerCapability() + "\r\n");
                            }
                            builder.append("250 " + capabilities.get(capabilities.size() - 1).getServerCapability()
                                    + "\r\n");
                        }
                        return builder.toString();
                    case C_STARTTLS:
                        return "STARTTLS\r\n";
                    case S_STARTTLS:
                        return "220 Go ahead with TLS negotiation\r\n";
                    case C_NOOP:
                        return "NOOP\r\n";
                    case S_OK:
                        return "250 OK\r\n";
                    case C_QUIT:
                        return "QUIT\r\n";
                    case S_BYE:
                        return "221 OK\r\n";
                }

            }
        }
        return "";
    }

    public String createExpectedCommand(CommandType commandType) {
        switch (starttlsType) {
            case IMAP: {
                switch (commandType) {
                    case C_CAPA:
                        return "CAPABILITY";
                    case C_STARTTLS:
                        return "STARTTLS";
                    case C_QUIT:
                        return "LOGOUT";
                }
            }
            case POP3:
                switch (commandType) {
                    case C_STARTTLS:
                        return "STLS";
                    case C_QUIT:
                        return "QUIT";
                }

            case SMTP:
                switch (commandType) {
                    case C_CAPA:
                        return "EHLO";
                    case C_STARTTLS:
                        return "STARTTLS";
                    case C_QUIT:
                        return "QUIT";
                }
        }
        return null;
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
        S_BYE,
        S_ERR
    }
}
