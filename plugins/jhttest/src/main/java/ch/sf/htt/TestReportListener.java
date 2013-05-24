/*
 * Author            : AdNovum Informatik AG
 * Version Number    : $Revision: $
 * Date of last edit : $Date: $
 */

package ch.sf.htt;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;

/**
 * @author ia97lies@sourceforge.net
 */
public class TestReportListener implements ITestListener {
    private BufferedWriter reportWriter;
    private String error = "";
	
	public TestReportListener(String pathToReport) throws IOException {
		File report;
		FileWriter fw;
		report = new File(pathToReport);
		report.getParentFile().mkdirs();
		report.createNewFile();
		report.setWritable(true, true);
		fw = new FileWriter(report.getAbsoluteFile());
		this.reportWriter = new BufferedWriter(fw);
	}
	
	/* (non-Javadoc)
	 * @see ch.sf.htt.ITestListener#addStandardOutput(java.lang.String)
	 */
	@Override
	public void addStandardOutput(String text) {
		try {
			this.reportWriter.write(text);
			this.reportWriter.append('\n');
		}
		catch (IOException ioe) { }
	}

	/* (non-Javadoc)
	 * @see ch.sf.htt.ITestListener#addErrorOutput(java.lang.String)
	 */
	@Override
	public void addErrorOutput(String text) {
		error += text + '\n';
	}

	/* (non-Javadoc)
	 * @see ch.sf.htt.ITestListener#setState(ch.sf.htt.ITestListener.STATE)
	 */
	@Override
	public void setState(STATE state) {
		try {
			if (state == STATE.FAILED) {
				this.reportWriter.flush();
			}
			if (state != STATE.RUNNING) {
				this.reportWriter.write(this.error);
				this.reportWriter.flush();
			}
		}
		catch (IOException ioe) { }
	}

}
