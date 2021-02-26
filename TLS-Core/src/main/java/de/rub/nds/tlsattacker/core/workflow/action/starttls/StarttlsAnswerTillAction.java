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
import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.action.AsciiAction;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.xml.bind.annotation.XmlTransient;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class StarttlsAnswerTillAction extends AsciiAction {

    private static final Logger LOGGER = LogManager.getLogger();

    private String expectedMessage;

    private StarttlsType starttlsType;

    private StarttlsMessageFactory factory;

    private List<String> receivedMessages;

    @XmlTransient
    private boolean unexpectedMessage;

    public StarttlsAnswerTillAction() {
        super();
    }

    public StarttlsAnswerTillAction(Config config, String expectedMessage, String encoding) {
        super(encoding);
        this.expectedMessage = expectedMessage;
        this.starttlsType = config.getStarttlsType();
        this.factory = new StarttlsMessageFactory(config);
        receivedMessages = new ArrayList<String>();
        unexpectedMessage = false;
    }

    /**
     * Communicate with Client until expected command was issued. Handled
     * Protocol messages: SMTP: EHLO, NOOP, QUIT, (STARTTLS) IMAP: CAPABILITY,
     * NOOP, LOGOUT, (STARTTLS) POP3: CAPA, QUIT, (STARTTLS)
     * 
     * @param state
     * @throws WorkflowExecutionException
     */
    @Override
    public void execute(State state) throws WorkflowExecutionException {
        TlsContext tlsContext = state.getTlsContext();

        if (isExecuted()) {
            throw new WorkflowExecutionException("Action already executed!");
        }
        try {
            LOGGER.debug("Receiving STARTTLS Messages...");
            while (true) {
                byte[] fetchData = tlsContext.getTransportHandler().fetchData();

                String receivedMessage = new String(fetchData, getEncoding());
                if (receivedMessage == null || receivedMessage.isEmpty())
                    break;

                receivedMessages.add(receivedMessage);

                if (receivedMessage.contains(expectedMessage)) {
                    if (starttlsType == StarttlsType.IMAP)
                        tlsContext.setRecentIMAPTag(receivedMessage.split(" ")[0]);
                    setExecuted(true);
                    break;
                }

                else {

                    String answer = "";
                    // Answer to specific protocol commands.
                    switch (starttlsType) {
                        case FTP:
                            break;
                        case IMAP: {
                            String IMAPTag = receivedMessage.split(" ")[0];
                            tlsContext.setRecentIMAPTag(IMAPTag);
                            if (receivedMessage.contains("NOOP"))
                                answer = factory.createCommand(StarttlsMessageFactory.CommandType.S_OK, IMAPTag);
                            else if (receivedMessage.contains("CAPABILITY"))
                                answer = factory.createCommand(StarttlsMessageFactory.CommandType.S_CAPA, IMAPTag);
                            else if (receivedMessage.contains("LOGOUT")) {
                                answer = factory.createCommand(StarttlsMessageFactory.CommandType.S_BYE, IMAPTag);
                                // TODO: Terminate connection.
                            } else
                                setUnexpectedMessage(true);
                            break;
                        }
                        case POP3: {
                            if (receivedMessage.contains("CAPA"))
                                answer = factory.createSendCommand(StarttlsMessageFactory.CommandType.S_CAPA);
                            if (receivedMessage.contains("QUIT"))
                                answer = factory.createSendCommand(StarttlsMessageFactory.CommandType.S_BYE);
                            else
                                setUnexpectedMessage(true);
                            // TODO: Terminate connection.
                            break;
                        }
                        case SMTP: {
                            if (receivedMessage.contains("NOOP"))
                                answer = factory.createSendCommand(StarttlsMessageFactory.CommandType.S_OK);
                            if (receivedMessage.contains("EHLO") && !"EHLO".equals(expectedMessage))
                                answer = factory.createSendCommand(StarttlsMessageFactory.CommandType.S_CAPA);
                            if (receivedMessage.contains("QUIT"))
                                answer = factory.createSendCommand(StarttlsMessageFactory.CommandType.S_BYE);
                            setUnexpectedMessage(true);
                            // TODO: Terminate connection.
                            break;
                        }
                    }
                    LOGGER.debug("Responding: " + answer);
                    tlsContext.getTransportHandler().sendData(answer.getBytes(getEncoding()));
                }
            }
            setAsciiText(String.join("", receivedMessages));
            LOGGER.info("Received Messages from StarttlsAnswerTillAction: " + getAsciiText());

        } catch (IOException e) {
            LOGGER.debug(e);
            setExecuted(false);
        }
    }

    @Override
    public void reset() {

    }

    public void setUnexpectedMessage(boolean unexpectedMessage) {
        this.unexpectedMessage = unexpectedMessage;
    }

    public boolean ReceivedUnexpectedMessage() {
        return unexpectedMessage;
    }

    public List<String> getReceivedMessages() {
        return receivedMessages;
    }

    @Override
    public boolean executedAsPlanned() {
        return isExecuted();
    }
}
