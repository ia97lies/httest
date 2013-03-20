/*
 * $Id: Httest.java,v 1.4 2012/02/18 15:32:52 msc Exp $
 * 
 * @Copyright: Marcel Schoen, Switzerland, 2012, All Rights Reserved.
 */
package ch.sf.htt;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

/**
 * Wrapper for running httest.
 *
 * @author Alain Stalder
 * @version $Revision: 1.4 $
 */
public class Httest {

	/** Constant for name of system property which holds httest version. */
	public static final String VERSION_PROPERTY = "httest.version";

	private File workingDir;
	private Environment environment;
	private boolean verbose = false;

	private File binariesDir;

	private boolean interrupted = false;

	/** Reference to the httest process standard output stream handler. */
	private ProcessStreamHandler outHandler = null;

	/** Reference to the httest process standard error stream handler. */
	private ProcessStreamHandler errHandler = null;

	/** Reference to the external httest process. */
	private Process proc = null;

	/** Stores the error of a failed test. */
	private List<HttestError> httestErrors = new ArrayList<HttestError>();

	private final static OperatingSystem OS = OperatingSystem.get();

	/**
	 * Creates a new Httest instance.
	 * 
	 * @return The Httest instance.
	 * @throws RuntimeException If the instance could not be created.
	 */
	public static Httest instance(Properties props) {
		try {
			return new Httest(props);
		} catch (IOException e) {
			throw new RuntimeException("could not create Httest instance", e);
		}
	}

	/**
	 * Creates new instance.
	 * 
	 * Initially scriptsDir and workingDir are set to the current directory;
	 * verbose is false and the environment is inherited from this process.
	 * 
	 * Copies binaries to a subdir in the temp directory if they are not already there.
	 * 
	 * @throws IOException
	 */
	private Httest(Properties props) throws IOException {
		String httestHome = props.getProperty("HTTEST_HOME");
		binariesDir = new File(httestHome);
		environment = new Environment();
	}

	/**
	 * Run the script with the given file name and path relative
	 * to the scriptDir.
	 * 
	 * @param scriptFileName
	 * @param commandLineArgs Optional command line arguments for the executed binary.
	 * @throws IOException
	 */
	public ExecResult runScript(String scriptFileName, String ... commandLineArgs) throws IOException, HttestFailedException {
		return runScript(null, scriptFileName, commandLineArgs);
	}

	/**
	 * Run the script with the given file name and path relative
	 * to the scriptDir.
	 * 
	 * @param console The console output window (for the GUI). Is null in command-line mode.
	 * @param scriptFileName The name of the httest script to execute.
	 * @param commandLineArgs Optional command line arguments for the executed binary.
	 * @throws IOException
	 */
	public ExecResult runScript(ITestListener console, String scriptFileName, String ... commandLineArgs) throws IOException, HttestFailedException {
		File scriptFile = new File(workingDir, scriptFileName);
		if (!scriptFile.exists()) {
			throw new FileNotFoundException("Missing script file: " + scriptFile.getAbsolutePath());
		}
		ExecResult execResult = executeBinary(scriptFile, console, commandLineArgs);

		if(!interrupted) {
			if (execResult.getReturnCode() != 0 || console != null) {
				List<String> errs = execResult.getStandardErr();
				if (execResult.getReturnCode() != 0) {
					throw new HttestFailedException("httest failed. RC: " + execResult.getReturnCode()
							+ ", stderr: " + errs.get(errs.size() - 1), execResult);
				}
			}
		} else {
			throw new HttestFailedException("httest was interrupted", execResult);
		}
		return execResult;
	}

	/**
	 * Runs the httest binary with the argument "-V" and returns
	 * the version number.
	 * 
	 * @return The version number, or null, if the binary could not be
	 *         properly executed.
	 * @throws IOException
	 * @throws IllegalStateException
	 */
	public String testBinary() throws IOException {
		ExecResult result = null;
		File httestFile = getHttestBinaryExecutableFile();
		String[] args = { httestFile.getCanonicalPath(), "-V" };
		result = doExecute(null, args);
		String firstLine = result.getStandardOut().get(0);
		if(firstLine.trim().indexOf(" ") != -1) {
			String version = firstLine.substring(firstLine.indexOf(" ") + 1);
			System.setProperty(VERSION_PROPERTY, version);
			return version;
		}
		// Getting the version did not work, so show debug info in stdout
		if(result != null) {
			// TODO: Refactor this outputting properly
			for(String line : result.getStandardOut()) {
				System.out.println("stdout> " + line);
			}
			for(String line : result.getStandardErr()) {
				System.out.println("stderr> " + line);
			}
		}
		throw new IllegalStateException("Failed to detect 'httest' executable version!");
	}

	/**
	 * Executes the given htt script with httest.
	 * 
	 * @param scriptFile The path of the .htt script file.
	 * @param commandLineArgs Optional command line arguments for the htt binary (may be empty or null).
	 * @return The execution result.
	 * @throws IOException
	 */
	private ExecResult executeBinary(File scriptFile, ITestListener listener, String ... commandLineArgs) throws IOException {
		File httestFile = getHttestBinaryExecutableFile();
		String[] args = new String[2];
		if(commandLineArgs != null && commandLineArgs.length > 0) {
			args = new String[2 + commandLineArgs.length];
			int argNo = 1;
			for(int pos = 0; pos < commandLineArgs.length; pos++) {
				args[argNo] = commandLineArgs[pos];
				if(commandLineArgs[pos] == null) {
					throw new IllegalStateException("INVALID ARGUMENT: " + pos);
				}
				argNo++;
			}
		}
		args[0] = httestFile.getCanonicalPath();
		args[args.length - 1] = scriptFile.getCanonicalPath();

		ExecResult result = doExecute(listener, args);
		return result;
	}

	/**
	 * Executes a httest binary with some commandline arguments.
	 * 
	 * @param listener A listener to test events.
	 * @param args The commandline arguments.
	 * @return The execution result.
	 */
	private ExecResult doExecute(ITestListener listener, String[] args) {
		interrupted = false;
		for(int pos = 0; pos < args.length; pos++) {
			String arg = args[pos];
			if(arg == null) {
				throw new IllegalStateException("NULL ARGUMENT: " + pos);
			} else {
				System.out.println(">> htt argument: " + arg);
			}
		}

		String[] envp = environment.getEnvp();
		ExecResult result = null;
		try {
			if(listener != null) {
				listener.setState(ITestListener.STATE.RUNNING);
			}
			proc = Runtime.getRuntime().exec(args, envp, workingDir);
			outHandler = new ProcessStreamHandler(proc.getInputStream(), "stdout", listener);
			outHandler.setVerbose(isVerbose());
			errHandler = new ProcessStreamHandler(proc.getErrorStream(), "stderr", listener);
			errHandler.setVerbose(isVerbose());
			outHandler.start();
			errHandler.start();

			// Wait for both to complete
			int ret = proc.waitFor();
			outHandler.join();
			errHandler.join();

			if(!outHandler.hasCompleted()) {
				listener.setState(ITestListener.STATE.INVALID);
				throw new IllegalStateException("stdout-handler not completed!");
			}
			if(!errHandler.hasCompleted()) {
				listener.setState(ITestListener.STATE.INVALID);
				throw new IllegalStateException("stderr-handler not completed!");
			}

			result = new ExecResult(ret, outHandler.getText(), errHandler.getText());
			if(listener != null) {
				if(result.wasSuccessful()) {
					listener.setState(ITestListener.STATE.SUCCESS);
				} else {
					if(interrupted) {
						listener.setState(ITestListener.STATE.STOPPED);
					} else {
						listener.setState(ITestListener.STATE.FAILED);
					}
				}
			}

			// Analyze error message(s)
			List<String> stdErr = result.getStandardErr();
			if(stdErr != null && stdErr.size() > 0) {
				for(String line : stdErr) {
					// Error information is in the first non-empty line
					if(line.trim().length() > 0 && line.indexOf(":") > 0) {
						httestErrors.add(processErrorMessage(line));
					}
				}
			}

		} catch (Exception e) {
			System.out.println("--------------> Execution of " + args[0] + " failed.");
			e.printStackTrace();
		}
		return result;
	}

	/**
	 * Processes the standard error output line of the httest
	 * binary and wraps the error information.
	 * 
	 * @param line The stderr output line.
	 * @return The error wrapper object.
	 */
	private HttestError processErrorMessage(String line) {
		try {
			if(line.indexOf(":") > 0) {
				String fileName = line.substring(0, line.indexOf(":"));
				// Cut off the first ":" which is left of the line number
				String msg = line.substring(line.indexOf(":") + 1);
				// Extract line number
				String lineNoTxt = msg.substring(0, msg.indexOf(":"));
				// Extract error message string
				String errMsg = msg.substring(msg.indexOf("error:") + 7);
				System.out.println("--> filename: " + fileName);
				System.out.println("--> line number: " + lineNoTxt);
				System.out.println("--> message: " + errMsg);
				return new HttestError(new File(fileName), Integer.parseInt(lineNoTxt), errMsg);
			}
		} catch(Exception ex) {
			// Invalid error message string
			System.err.println("Invalid error message, unable to process: " + line);
		}
		return null;
	}

	/**
	 * Returns the errors in case there was one.
	 * 
	 * @return The errors because of which the test failed.
	 */
	public List<HttestError> getErrors() {
		return httestErrors;
	}

	/**
	 * Interrupts the executed process.
	 */
	public void interruptExecution() {
		if(proc != null) {
			interrupted = true;
			outHandler.interrupt();
			errHandler.interrupt();
			proc.destroy();
		}
	}

	/**
	 * Allows to check if this httest execution was interrupted.
	 * 
	 * @return True if the user interrupted the test.
	 */
	public boolean isInterrupted() {
		return interrupted;
	}

	/**
	 * Gets file for httest executable.
	 * 
	 * @return
	 */
	public File getHttestBinaryExecutableFile() {
		return new File(binariesDir, getHttestBinaryExecutableFilename());
	}

	/**
	 * Gets file name of httest executable; "httest.exe" on windows
	 * and "httest" on unix.
	 * 
	 * @return file name of httest executable
	 */
	public static String getHttestBinaryExecutableFilename() {
		if(OS == OperatingSystem.WINDOWS) {
			return "httest.exe";
		} else {
			return "httest";
		}
	}

	/**
	 * Gets file for htntlm executable.
	 * 
	 * @return
	 */
	public File getHtntlmFile() {
		return new File(binariesDir, getHtntlmFilename());
	}

	/**
	 * Gets file name of htntlm executable; "htntlm" on windows
	 * and "htntlm" on unix.
	 * 
	 * @return file name of htntlm executable
	 */
	public static String getHtntlmFilename() {
		if(OS == OperatingSystem.WINDOWS) {
			return "htntlm.exe";
		} else {
			return "htntlm";
		}
	}

	/**
	 * Gets the base directory for httest scripts.
	 * 
	 * @return the scriptsDir
	 */
//	public File getScriptsDir() {
//		return scriptsDir;
//	}
//
//	/**
//	 * Sets the base directory for httest scripts.
//	 * 
//	 * @param scriptsDir the scriptsDir to set
//	 */
//	public void setScriptsDir(File scriptsDir) {
//		this.scriptsDir = scriptsDir;
//	}
//
//	/**
//	 * Gets the working directory to use when running httest.
//	 * 
//	 * @return the workingDir
//	 */
//	public File getWorkingDir() {
//		return workingDir;
//	}
//
//	/**
//	 * Sets the working directory to use when running httest.
//	 * 
//	 * @param workingDir the workingDir to set
//	 */
//	public void setWorkingDir(File workingDir) {
//		this.workingDir = workingDir;
//	}
//
//	/**
//	 * Gets the environment to use when running httest.
//	 * 
//	 * @return the environment
//	 */
//	public Environment getEnvironment() {
//		return environment;
//	}

	/**
	 * Sets the environment to use when running httest.
	 * 
	 * @param environment the environment to set
	 */
	public void setEnvironment(Environment environment) {
		this.environment = environment;
	}

	/**
	 * Get info if httest output is verbose, i.e. if always printing out
	 * httest output or only in case httest failed.
	 * 
	 * @return the verbose
	 */
	public boolean isVerbose() {
		return verbose;
	}

	/**
	 * Set info if httest output is verbose, i.e. if always printing out
	 * httest output or only in case httest failed.
	 * 
	 * @param verbose the verbose to set
	 */
	public void setVerbose(boolean verbose) {
		this.verbose = verbose;
	}

	/**
	 * Return the current operating system.
	 * 
	 * @return operating system
	 */
	public static OperatingSystem getOs() {
		return OS;
	}

	/**
	 * Return the directory that contains the httest binaries.
	 * 
	 * @return the binariesDir
	 */
	public File getBinariesDir() {
		return binariesDir;
	}

}
