/*
 * $Id: PropertiesUpdater.java,v 1.1 2011/12/21 21:22:30 msc Exp $
 * 
 * @Copyright: Marcel Schoen, Switzerland, 2012, All Rights Reserved.
 */
package ch.sf.htt;

import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;

/**
 * Utility class which creates the properties file with the information
 * about the binaries in the classpath.
 * 
 * @author Marcel Schoen
 * @version $Revision: 1.1 $, $Date: 2011/12/21 21:22:30 $
 */
public class PropertiesUpdater {

	/**
	 * Command line execution method.
	 * 
	 * @param args Command line arguments.
	 */
	public static void main(String[] args) {
		if(args != null && args.length == 4) {
			try {
				addInfo(args[0], args[1], args[2], args[3]);
			} catch(IllegalArgumentException e) {
				System.err.println("ERROR> " + e.getMessage());
				showUsage();
			} catch(Exception e) {
				e.printStackTrace();
			}
		} else {
			showUsage();
		}
	}

	/**
	 * Shows CLI usage instructions.
	 */
	private static void showUsage() {
		System.err.println("Usage: PropertiesUpdater <version> <platform> <directory> <properties-file>");
	}

	/**
	 * Adds information about the binaries in the given directory.
	 * 
	 * @param version The version of those binaries.
	 * @param platform The binaries platform, like "windows", "linux-x86" etc.
	 * @param directory The directory whose contents will be used to
	 *                  generate the list of binaries.
	 * @param propertiesFile The path of the properties file that must be
	 *                       created / updated.
	 */
	private static void addInfo(String version, String platform, String directory, String propertiesFile) throws Exception {
		if(version == null || version.trim().length() == 0) {
			throw new IllegalArgumentException("Version must not be empty!");
		}
		if(directory == null || directory.trim().length() == 0) {
			throw new IllegalArgumentException("Directory must not be invalid or null!");
		}
		String filelist = "";
		File dir = new File(directory);
		if(dir.exists() && dir.isDirectory()) {
			String[] contents = dir.list();
			boolean hasFiles = false;
			for(String entry : contents) {
				File single = new File(dir, entry);
				if(single.isFile()) {
					hasFiles = true;
					if(filelist.length() > 0) {
						filelist += ",";
					}
					filelist += single.getName();
				}
			}
			if(!hasFiles) {
				throw new IllegalStateException("Directory contains no files: " + directory);
			}
			File propsFile = new File(propertiesFile);
			PrintWriter wrt = null;
			try {
				wrt = new PrintWriter(new FileWriter(propsFile, true));
				wrt.println("");
				wrt.println("version." + platform + "=" + version);
				wrt.println("binaries." + platform + "=" + filelist);
				wrt.flush();
			} finally {
				wrt.close();
			}
		} else {
			throw new IllegalArgumentException("Directory invalid: " + directory);
		}
	}
}
