/*
 * $Id: HttUtil.java,v 1.1 2012/02/18 15:32:52 msc Exp $
 * 
 * @Copyright: Marcel Schoen, Switzerland, 2012, All Rights Reserved.
 */
package ch.sf.htt;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.Properties;

/**
 * Utility methods.
 * 
 * @author Marcel Schoen
 * @version $Revision: 1.1 $, $Date: 2012/02/18 15:32:52 $
 */
public class HttUtil {

	/** Constant for name of PDF file. */
	public static final String USERSGUIDE = "users-guide.pdf";

	/** Constant for property key prefix. */
	private static final String PREFIX_BINARIES = "binaries.";

	/**
	 * Reads a text file (template) from 
	 * the classpath.
	 * 
	 * @param resourceName The filename in the classpath.
	 * @return The contents as an array of strings.
	 * @throws Exception
	 */
	public static String[] getTextFileContent(String resourceName) throws Exception {
		ArrayList<String> contents = new ArrayList<String>();
		BufferedReader rd = null;
		InputStream from = null;
		try {
			from = HttUtil.class.getResourceAsStream(resourceName);
		    if(from != null) {
		    	rd = new BufferedReader(new InputStreamReader(from));
		    	String line = null;
		    	while((line = rd.readLine()) != null) {
		    		contents.add(line);
		    	}
		    }
		} finally {
			if(from != null) {
				from.close();
			}
		}
		return contents.toArray(new String[contents.size()]);
	}

	/**
	 * Reads a properties file from 
	 * the classpath.
	 * 
	 * @param resourceName The filename in the classpath.
	 * @return The contents as an array of strings.
	 * @throws Exception
	 */
	public static Properties getPropertiesFileContent(String resourceName) throws Exception {
		InputStream from = null;
		try {
			from = HttUtil.class.getResourceAsStream(resourceName);
		    if(from != null) {
		    	Properties props = new Properties();
		    	props.load(from);
		    	return props;
		    }
		} finally {
			if(from != null) {
				from.close();
			}
		}
		return null;
	}
	
    /**
	 * Returns a reference to the users-guide PDF file in the 
	 * temporary directory. If the file does not exist yet, it 
	 * is extracted from the classpath automatically.
	 * 
	 * @return The PDF file reference (may be null, if there was a problem
	 *         extracting the file).
	 * @throws Exception If the file could not be extracted / found.
	 */
	public static File getUsersGuideTempDoc() throws Exception {
		String tempDir = System.getProperty("java.io.tmpdir");
		File pdfFile = extractFileFromClasspath(tempDir, "/doc/" + USERSGUIDE, USERSGUIDE);
		return pdfFile;
	}

	/**
	 * Allows to check if a given resource exists in the classpath.
	 * 
	 * @param resourcePath Name of file (absolute path within classpath)
	 * @return True if it exists.
	 */
	public static boolean resourceExists(String resourcePath) {
		boolean exists = false;
		try {
			HttUtil.class.getResourceAsStream(resourcePath);
			exists = true;
		} catch(Exception ex) {
			// ignore
		}
		return exists;
	}
	
	/**
	 * Extracts a file from the classpath into the filesystem.
	 * 
	 * @param targetDir The directory path where the extracted file should be stored.
	 * @param resourcePath Name of file (absolute path within classpath)
	 * @param fileName The simple name of the file to extract (without path).
	 * @return The reference to the extracted file.
	 * @throws FileNotFoundException
	 * @throws IOException
	 */
	public static File extractFileFromClasspath(String targetDir, String resourcePath, String fileName)
			throws FileNotFoundException, IOException {
		File pdfFile = new File(targetDir, fileName);
		if(!pdfFile.exists()) {
			OutputStream out = null; 
			InputStream from = null;
			try {
				from = HttUtil.class.getResourceAsStream(resourcePath);
			    if(from != null) {
				    out = new FileOutputStream(pdfFile);
				    byte[] buffer = new byte[16584];
				    int len = -1;
				    while((len = from.read(buffer)) != -1) {
				    	out.write(buffer, 0, len);
				    }
				    out.flush();
			    } else {
			    	throw new IllegalArgumentException("Resource does not exist: " + resourcePath);
			    }
			} finally {
				if(out != null) {
					out.close();
				}
				if(from != null) {
					from.close();
				}
			}
		}
		return pdfFile;
	}

	/**
	 * Extracts the "httest" binaries of all platforms 
	 * to the given directory (into a newly created sub-directory 
	 * "htt-binaries").
	 * 
	 * @param directory The directory where the binaries are extracted to.
	 */
	public static void extractHttBinaries(File directory) throws Exception {
		Properties httProps = getPropertiesFileContent("/htt/htt.properties");
		File binariesBaseDir = new File(directory, "htt-binaries");
		Enumeration keys = httProps.keys();
		while(keys.hasMoreElements()) {
			String key = (String)keys.nextElement();
			if(key.startsWith(PREFIX_BINARIES)) {
				String platform = key.substring(PREFIX_BINARIES.length());
				File binaryDir = new File(binariesBaseDir, platform);
				binaryDir.mkdirs();
				if(binaryDir.exists()) {
					String[] binaryNames = ((String)httProps.get(PREFIX_BINARIES + platform)).split(",");
					for (String binaryName : binaryNames) {
						File binaryFile = extractFileFromClasspath(binaryDir.getAbsolutePath(), 
								"/htt/bin/" + platform + "/" + binaryName, binaryName);
						System.out.println("Extracted binary: " + binaryFile.getAbsolutePath());
					}
				} else {
					String msg = "ERROR: Failed to create binaries directory: " + binaryDir.getAbsolutePath();
					System.err.println(msg);
					throw new IllegalStateException(msg);
				}
			}
		}
	}
}
