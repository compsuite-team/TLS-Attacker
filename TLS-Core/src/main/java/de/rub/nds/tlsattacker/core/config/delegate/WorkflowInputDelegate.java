/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.config.delegate;

import com.beust.jcommander.Parameter;
import de.rub.nds.tlsattacker.core.config.TlsConfig;
import java.io.FileInputStream;
import org.apache.logging.log4j.LogManager;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class WorkflowInputDelegate extends Delegate {

    private static final org.apache.logging.log4j.Logger LOGGER = LogManager.getLogger("Config");

    @Parameter(names = "-workflow_input", description = "This parameter allows you to load the whole workflow trace from the specified XML configuration file")
    private String workflowInput = null;

    public WorkflowInputDelegate() {
    }

    public String getWorkflowInput() {
        return workflowInput;
    }

    public void setWorkflowInput(String workflowInput) {
        this.workflowInput = workflowInput;
    }

    @Override
    public void applyDelegate(TlsConfig config) {
        FileInputStream fis = null;
        if (workflowInput != null) {
            config.setWorkflowInput(workflowInput);
        }
    }
}
