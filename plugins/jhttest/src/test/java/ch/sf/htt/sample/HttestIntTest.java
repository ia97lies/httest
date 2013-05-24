/*
 * Author            : AdNovum Informatik AG
 * Version Number    : $Revision: $
 * Date of last edit : $Date: $
 */

package ch.sf.htt.sample;

import java.io.FileInputStream;
import java.util.Collection;
import java.util.Properties;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

import ch.sf.htt.HttestWrapper;
import ch.sf.htt.ITestListener;
import ch.sf.htt.TestReportListener;

/**
 * A test class to run all httest scripts below $basedir/src/test/httest
 * @author ia97lies@sourceforge.net
 */
@RunWith(Parameterized.class)
public class HttestIntTest extends HttestWrapper {

	public HttestIntTest(String file) {
		super(file);
	}
	
	private static Properties getProperties() throws Exception {
		Properties props;
		props = new Properties();
		props.load(new FileInputStream("/home/cli/.htt/htt.properties"));
		props.setProperty("basedir", "/home/cli/projects/htt/plugins/jhttest");
		props.setProperty("scriptdir", "src/test/httest");
		props.setProperty("reportdir", "spool/reports");
		return props;
	}
	
	/**
	 * setup httest
	 * @note: you could activate verbose as well here, should be able to set with properties
	 */
	@Override
	@Before
	public void setUp() throws Exception {
		super.setUp(HttestIntTest.getProperties());
		setVerbose(true);
	}

	/**
	 * Collect all files below $basedir/src/test/httest
	 * @return return collection
	 * @note: this is used vor parametrized junit tests
	 */
	@Parameters(name="{index}: {0}")
	public static Collection<Object[]> data() throws Exception {
		Properties props = HttestIntTest.getProperties();
		return collectHttestScript(props);
	}

	/**
	 * Test runner
	 * @throws Exception
	 */
	@Test
	public void httTests() throws Exception {
		ITestListener console = new TestReportListener(HttestIntTest.getProperties().getProperty("reportdir")+"/"+file+".out");
		
		getHttest().runScript(console, HttestIntTest.getProperties().getProperty("scriptdir")+"/"+file);
	}
}
