/*
 * $Id: Environment.java,v 1.1 2011/11/16 08:53:13 msc Exp $
 * 
 * @Copyright: Marcel Schoen, Switzerland, 2012, All Rights Reserved.
 */
package ch.sf.htt;

import java.io.File;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;


/**
 * Abstracts environment variables; names of environment variables
 * are all stored lower case, e.g. "path".
 * 
 * All methods that are given names of environment variables can use
 * any case, i.e. are converted to lower case within the method;
 * returned names of environment variables are all lower case.
 *
 * @author Alain Stalder
 * @version $Revision: 1.1 $
 */
public class Environment {

	Map<String,String> environment;

	/**
	 * Constructor from explicit environment map, given in same format
	 * as returned by System.getenv().
	 * 
	 * @param environmentMap environment map
	 */
	public Environment(Map<String,String> environmentMap) {
		// convert keys to all lower case
		environment = new TreeMap<String,String>();
		for (String key : environmentMap.keySet()) {
			environment.put(key.toLowerCase(), environmentMap.get(key));
		}
	}

	/**
	 * Constructor, gets same environment as current process.
	 */
	public Environment() {
		this(System.getenv());
	}


	/**
	 * Add path directory to path environment variable.
	 * 
	 * @param dir directory
	 */
	public void addToPath(String dir) {
		String path = environment.get("path");
		if (path == null) {
			path = dir;
		}  else {
			path+= System.getProperty("path.separator") + dir;
		}
		environment.put("path", path);
	}

	/**
	 * Add path directory file to path environment variable.
	 * 
	 * @param dir directory file
	 */
	public void addToPath(File dir) {
		addToPath(dir.getAbsolutePath());
	}

	/**
	 * Get environment array in format needed for Runtime().exec(),
	 * i.e. as array of "<key>=<value>" strings.
	 * 
	 * @return environment array
	 */
	public String[] getEnvp() {
		List<String> env = new LinkedList<String>();
		for (String key : environment.keySet()) {
			env.add(key + "=" + environment.get(key));
		}
		String[] envp = new String[env.size()];
		return env.toArray(envp);
	}

	/**
	 * @return the environment map
	 */
	public Map<String, String> getEnvironmentMap() {
		return environment;
	}

	/**
	 * Return value for given key; converts key to lower case first.
	 * 
	 * @param key key
	 * @return value, null if does not exist in environment
	 */
	public String getValue(String key) {
		return environment.get(key.toLowerCase());
	}

}
