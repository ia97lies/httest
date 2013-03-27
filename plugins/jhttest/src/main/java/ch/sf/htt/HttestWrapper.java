/*
 * $Id: HttestWrapper.java,v 1.1 2011/11/16 08:53:13 msc Exp $
 * 
 * @Copyright: Marcel Schoen, Switzerland, 2012, All Rights Reserved.
 */
package ch.sf.htt;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
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

	private Httest httest;
	protected String file;

	public HttestWrapper(String file) {
		this.file = file;
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
	
	/**
	 * Collect all files below a folder like $basedir/src/test/httest
	 * @param file IN staring point to collect httest scripts
	 * @param all IN a collection of script names
	 */
	public static Collection<Object[]> collectHttestScript(Properties props) {
		Collection<Object[]> data = new ArrayList<Object[]>();
		addHttestScripts(new File(props.getProperty("basedir")+"/"+props.getProperty("scriptdir")), data, props.getProperty("scriptdir"));	
		return data;
	}
	
	private static void addHttestScripts(File file, Collection<Object[]> all, String prefix) {
		File[] children = file.listFiles();
		if (children != null) {
			for (File child : children) {
				if (child.isFile()) {
					String script = prefix+"/"+file.getName()+"/"+child.getName();
					Object[] data = new Object[] { script };
					all.add(data);
				}
				addHttestScripts(child, all, prefix);
			}
		}
	}
}
