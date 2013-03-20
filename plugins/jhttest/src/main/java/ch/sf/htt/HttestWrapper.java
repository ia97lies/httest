/*
 * $Id: HttestWrapper.java,v 1.1 2011/11/16 08:53:13 msc Exp $
 * 
 * @Copyright: Marcel Schoen, Switzerland, 2012, All Rights Reserved.
 */
package ch.sf.htt;

import java.io.IOException;
import java.util.Properties;

/**
 * Base test case for httest tests.
 * 
 * Typically you extend this class and then set scripts dir,
 * working dir, enviroment and verbose in a setUp() method
 * or for individual tests.
 *
 * @author Alain Stalder
 * @author Marcel Schoen
 * @version $Revision: 1.1 $
 */
public class HttestWrapper {

	private final String testName;
	private Httest httest;

	/**
	 * Creates the test suite.
	 */
	public HttestWrapper() {
		testName = null;
	}

	/**
	 * Creates the test suite.
	 */
	public HttestWrapper(String testName) {
		this.testName = testName;
	}

	/**
	 * Get test name.
	 * 
	 * @return test name
	 */
	public String getTestName() {
		return testName;
	}

	/** Gets httest instance.
	 * 
	 * @return instance
	 */
	public Httest getHttest() {
		return httest;
	}

	public void setUp() throws Exception {
		
	}
	
	/**
	 * 
	 * @throws Exception
	 */
	public void setUp(Properties props) throws Exception {
		httest = Httest.instance(props);
	}

	/**
	 * Convenience method for running httest script.
	 * 
	 * @param scriptFileName httest script file name
	 * @throws IOException
	 */
	public ExecResult runScript(String scriptFileName) throws IOException, HttestFailedException {
		return httest.runScript(scriptFileName);
	}

	/**
	 * Convenience method for setting httest scripts dir.
	 * 
	 * @param scriptsDir httest scripts dir
	 */
//	public void setScriptsDir(File scriptsDir) {
//		httest.setScriptsDir(scriptsDir);
//	}
//
//	/**
//	 * Convenience method for setting httest working dir.
//	 * 
//	 * @param workingDir httest working dir
//	 */
//	public void setWorkingDir(File workingDir) {
//		httest.setWorkingDir(workingDir);
//	}

	/**
	 * Convenience method for setting httest environment.
	 * 
	 * @param environment httest environment
	 */
	public void setEnvironment(Environment environment) {
		httest.setEnvironment(environment);
	}

	/**
	 * Convenience method for setting httest verbose.
	 * 
	 * @param verbose httest verbose
	 */
	public void setVerbose(boolean verbose) {
		httest.setVerbose(verbose);
	}
}
