/*
 * $Id: ExecResult.java,v 1.1 2011/11/16 08:53:13 msc Exp $
 * 
 * @Copyright: Marcel Schoen, Switzerland, 2012, All Rights Reserved.
 */
package ch.sf.htt;

import java.util.List;

/**
 * Container for results of Runtime.exec() calls, immutable class.
 *
 * @author Marcel Schoen
 * @version $Revision: 1.1 $
 */
public class ExecResult {

	/**
	 * Internal values.
	 */
	final private int returnCode;
	final private List<String> standardOut;
	final private List<String> standardErr;

	/**
	 * Constructor. Usually you do not use this by yourself.
	 * 
	 * @param returnCode
	 *            The return code.
	 * @param standardOut
	 *            A list of strings where each entry will be a line for the output stream.
	 * @param standardErr
	 *            A list of strings where each entry will be a line for the error stream.
	 */
	public ExecResult(int returnCode, List<String> standardOut, List<String> standardErr) {
		this.returnCode = returnCode;
		this.standardOut = standardOut;
		this.standardErr = standardErr;
	}

	/**
	 * Allows to check if the test completed successfully.
	 * 
	 * @return True if the test was successful.
	 */
	public boolean wasSuccessful() {
		if(returnCode == 0) {
			if(standardOut != null && standardOut.size() > 0) {

			}
			return true;
		}
		return false;
	}

	/**
	 * Get the platform-specific return code of the external process.
	 * 
	 * @return The return code of the process.
	 */
	public int getReturnCode() {
		return returnCode;
	}

	/**
	 * Get all text that was produced by the external process on standard error.
	 *
	 * @return A list of strings where every entry is one
	 *         line of the process standard error output.
	 */
	public List<String> getStandardErr() {
		return standardErr;
	}

	/**
	 * Get all text that was produced by the external
	 * process on standard out.
	 *
	 * @return A String-array whereas every entry is one
	 *         line of the process standard output.
	 */
	public List<String> getStandardOut() {
		return standardOut;
	}
}
