/*
 * $Id: OperatingSystem.java,v 1.2 2011/12/21 21:22:30 msc Exp $
 * 
 * @Copyright: Marcel Schoen, Switzerland, 2012, All Rights Reserved.
 */
package ch.sf.htt;



/**
 * Enum that abstracts an operating system.
 *
 * @author Alain Stalder
 * @version $Revision: 1.2 $
 */
public enum OperatingSystem {

	UNKNOWN,
	WINDOWS,
	SOLARIS,
	LINUX,
	MACOS,
	HPUX;

	/**
	 * Get the current operating system, i.e. the operating system
	 * from which this method is called.
	 * 
	 * @return operating system
	 */
	public static OperatingSystem get() {
		String os = System.getProperty("os.name").toLowerCase();
		if (os.startsWith("sunos")) {
			return SOLARIS;
		} else if (os.startsWith("hp ux")) {
			return HPUX;
		} else if (os.startsWith("mac os")) {
			return MACOS;
		}  else if (os.startsWith("windows")) {
			return WINDOWS;
		}  else if (os.startsWith("linux")) {
			return LINUX;
		} else {
			return UNKNOWN;
		}
	}

}
