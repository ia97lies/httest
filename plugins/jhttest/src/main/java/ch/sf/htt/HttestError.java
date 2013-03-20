/*
 * $Header: $
 * 
 * @Copyright: Marcel Schoen, Switzerland, 2012, All Rights Reserved.
 */

package ch.sf.htt;

import java.io.File;

/**
 * Contains information about a script error.
 *
 * @author Marcel Schoen
 * @version $Revision: $
 */
public class HttestError {

	/** The httest script file with the error. */
	private File httestScript = null;

	/** The line number where the error occured. */
	private int lineNumber = -1;

	/** The (first) error message. */
	private String message = "";

	/**
	 * Creates an error wrapper.
	 * 
	 * @param httestScript The httest script with the error.
	 * @param lineNumber The line number where the error occured.
	 * @param message The (first) error message.
	 */
	public HttestError(File httestScript, int lineNumber, String message) {
		this.httestScript = httestScript;
		this.lineNumber = lineNumber;
		this.message = message;
	}

	/**
	 * @return the httestScript
	 */
	public File getHttestScript() {
		return httestScript;
	}

	/**
	 * @return the lineNumber
	 */
	public int getLineNumber() {
		return lineNumber;
	}

	/**
	 * @return the message
	 */
	public String getMessage() {
		return message;
	}
}
