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
import de.rub.nds.tlsattacker.core.starttls.StarttlsCommandType;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.action.AsciiAction;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.xml.bind.annotation.XmlTransient;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class StarttlsAnswerTillAction extends StarttlsAsciiAction {

    private static final Logger LOGGER = LogManager.getLogger();

    private StarttlsCommandType expectedMessage;

    private List<String> receivedMessages;

    public StarttlsAnswerTillAction() {
        super();
    }

    public StarttlsAnswerTillAction(Config config, StarttlsCommandType expectedMessage, String encoding) {
        super(encoding, config);
        this.expectedMessage = expectedMessage;
        receivedMessages = new ArrayList<String>();
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
                if (receivedMessage == null || receivedMessage.isEmpty()) {
                    break;
                }
                receivedMessages.add(receivedMessage);

                if (getType() == StarttlsType.IMAP)
                    tlsContext.setRecentIMAPTag(receivedMessage.split(" ")[0]);

                if (receivedCmd(receivedMessage, expectedMessage)) {
                    setExecuted(true);
                    break;
                }

                else {

                    String answer = "";
                    for (StarttlsCommandType type : getHandler().expectedCommandsDict().keySet()) {
                        if (receivedCmd(receivedMessage, type))
                            answer = getHandler().createCommand(tlsContext, getHandler().CommandsResponses().get(type));
                    }
                    if (answer.isEmpty())
                        answer = getHandler().createCommand(tlsContext, StarttlsCommandType.S_ERR);
                    // Answer to specific protocol commands.
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

    private boolean receivedCmd(String receivedMessage, StarttlsCommandType commandType) {
        String cmd = getHandler().expectedCommandsDict().get(commandType);
        String toCompare = receivedMessage.toUpperCase();
        return toCompare.contains(cmd);
    }

    public List<String> getReceivedMessages() {
        return receivedMessages;
    }

    @Override
    public boolean executedAsPlanned() {
        return isExecuted();
    }

    @Override
    public String getActionInfo() {
        return "StarttlsAnswerTillAction: Communicating until client issues \""
                + getHandler().expectedCommandsDict().get(expectedMessage) + "\"";
    }
}
