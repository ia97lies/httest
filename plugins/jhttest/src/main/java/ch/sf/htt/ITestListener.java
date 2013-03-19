/*
 * $Id: ITestListener.java,v 1.1 2011/12/08 16:24:14 msc Exp $
 * 
 * @Copyright: Marcel Schoen, Switzerland, 2012, All Rights Reserved.
 */
package ch.sf.htt;

/**
 * Interface for listeners for test status and output.
 * 
 * @author Marcel Schoen
 * @version $Revision: 1.1 $, $Date: 2011/12/08 16:24:14 $
 */
public interface ITestListener {

	/**
	 * More standard output data is received.
	 * 
	 * @param text The stdout data.
	 */
	void addStandardOutput(String text);

	/**
	 * More standard error data is received.
	 * 
	 * @param text The stderr data.
	 */
	void addErrorOutput(String text);

	/**
	 * Updates the state of the test.
	 * 
	 * @param state The current test state.
	 */
	void setState(STATE state);
	
	/** List of possible test states. */
	enum STATE {
		
		/** Test has not started yet */
		WAITING,
		
		/** Test is currently running */
		RUNNING,
		
		/** Test was successfuly completed */
		SUCCESS,
		
		/** Test was interrupted by user */
		STOPPED,
		
		/** Test did not complete due to some unexpected / internal error */
		INVALID,
		
		/** Test failed (doh!) */
		FAILED
	};
}
