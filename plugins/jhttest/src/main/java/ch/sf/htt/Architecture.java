/*
 * $Id: Architecture.java,v 1.1 2011/12/21 21:22:30 msc Exp $
 * 
 * @Copyright: Marcel Schoen, Switzerland, 2012, All Rights Reserved.
 */
package ch.sf.htt;

/**
 * Detects the architecture of the system.
 * 
 * @author Marcel Schoen
 * @version $Revision: 1.1 $, $Date: 2011/12/21 21:22:30 $
 */
public enum Architecture {

	UNKNOWN,
	X86,
	X86_64,
	SPARC;

	/**
	 * Get the current cpu architecture.
	 * 
	 * @return system architecture.
	 */
	public static Architecture get() {
		if(OperatingSystem.get() == OperatingSystem.WINDOWS) {
			// There's currently only 32-bit binaries for windows
			return X86;
		}
		String arch = System.getProperty("os.arch").toLowerCase();
		String vm = System.getProperty("java.vm.name").toLowerCase();
		if (arch.equals("amd64") || arch.equals("x86_64") || vm.indexOf("64-Bit") != -1) {

			// TODO: Implement detection of 64 bit cpu on Linux somehow

			return X86_64;
		} else if (arch.equals("x86") || arch.equals("i386") || arch.equals("i686")) {
			return X86;
		} else if (arch.indexOf("sparc") != -1) {
			return SPARC;
		} else {
			return UNKNOWN;
		}
	}

}
