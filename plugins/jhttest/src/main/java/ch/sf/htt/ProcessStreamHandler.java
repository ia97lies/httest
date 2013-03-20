/*
 * $Id: ProcessStreamHandler.java,v 1.2 2011/12/08 16:24:14 msc Exp $
 * 
 * @Copyright: Marcel Schoen, Switzerland, 2012, All Rights Reserved.
 */

package ch.sf.htt;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;

/**
 * Reads any input stream in a separate thread until
 * the stream is finished.
 * 
 * @author Marcel Schoen
 * @version $Revision: 1.2 $
 */
public class ProcessStreamHandler extends Thread {
	
	private InputStream inputStream;
	private String streamType = "<undefined>";
	private boolean completed = false;
	private List<String> text = null;
	private boolean verbose = false;
	
	private boolean interrupted = false;
	
	/** Flag for differentiating between stdout and stderr. */
	private boolean isError = false;
	
	/** Reference to a listener for the data read from the stream. */
	private ITestListener listener = null;
	
	/**
	 * Creates an instance of a process stream handler.
	 * 
	 * @param inputStream The InputStream that must be read.
	 * @param streamType The stream type (just a name, like "stdout").
	 */
	public ProcessStreamHandler(InputStream inputStream, String streamType, ITestListener listener) {
		this.inputStream = inputStream;
		this.streamType = streamType;
		this.listener = listener;
	}
	
	/**
	 * Creates an instance of a process stream handler.
	 * 
	 * @param inputStream The InputStream that must be read.
	 * @param streamType The stream type (just a name, like "stdout").
	 */
	public ProcessStreamHandler(InputStream inputStream, String streamType) {
		this.inputStream = inputStream;
		this.streamType = streamType;
	}

	/**
	 * Interrupts reading of this stream.
	 */
	public void interrupt() {
		this.interrupted = true;
	}
	
	/**
	 * Allows to enable or disable verbose output.
	 * 
	 * @param value If true, debug output is enabled.
	 */
	public void setVerbose(boolean value) {
		this.verbose = value;
	}
	
	/*
	 * (non-Javadoc)
	 * @see java.lang.Thread#run()
	 */
	@Override
	public void run() {
//		System.out.println(">>" + this.streamType + " - IS VERBOSE: " + this.verbose);
		try {
			text = new ArrayList<String>();
			BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));
			String line = null;
			while((line = reader.readLine()) != null) {
				if(verbose) {
					System.out.println(">>" + this.streamType + ": " + line);
				}
				if(this.listener != null) {
					if(this.isError) {
						this.listener.addErrorOutput(line);
					} else {
						this.listener.addStandardOutput(line);
					}
				}
				text.add(line);
			}
			reader.close();
		} catch(Exception e) {
			if(!interrupted) {
				e.printStackTrace();
			}
		} finally {
			try {
				inputStream.close();
			} catch (IOException e) {
				// ignore
			}
			completed = true;
		}
	}

	/**
	 * Returns the text read from the input stream as a list of strings.
	 * 
	 * @return The InputStream contents.
	 */
	public List<String> getText() {
		return text;
	}

	/**
	 * Returns true if the stream has been read completely.
	 * 
	 * @return True if the thread has finished.
	 */
	public boolean hasCompleted() {
		return completed;
	}
}