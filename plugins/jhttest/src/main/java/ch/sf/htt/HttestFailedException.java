/*
 * $Id: HttestFailedException.java,v 1.1 2011/11/16 08:53:13 msc Exp $
 * 
 * @Copyright: Marcel Schoen, Switzerland, 2012, All Rights Reserved.
 */
package ch.sf.htt;



/**
 * Exception thrown when httest fails by returning a return code != 0.
 * Contains an ExceResult.
 *
 * @author Alain Stalder
 * @version $Revision: 1.1 $
 */
public class HttestFailedException extends Exception {

	private static final long serialVersionUID = -3284005314635684793L;

	private ExecResult execResult;

	/**
	 * Constructor from message and exec result.
	 * 
	 * @param message message
	 * @param execResult exec result
	 */
	public HttestFailedException(String message, ExecResult execResult) {
		super(message);
		this.execResult = execResult;
	}

	/**
	 * @return the execResult
	 */
	public ExecResult getExecResult() {
		return execResult;
	}

}
