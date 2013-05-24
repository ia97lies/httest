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

import ch.sf.htt.HttestClassRunner;
import ch.sf.htt.HttestClassRunner.HttSubDir;
import ch.sf.htt.HttestWrapper;

/**
 * @author ia97lies@sourceforge.net
 */
@RunWith(HttestClassRunner.class)
public class HttestIntTestClassRunner extends HttestWrapper {
	public HttestIntTestClassRunner() {
		super("");
	}
	
	public static Properties getProperties() throws Exception {
		System.out.println("HEYHO");
		Properties props;
		props = new Properties();
		props.load(new FileInputStream("/home/cli/.htt/htt.properties"));
		props.setProperty("basedir", "/home/cli/projects/htt/plugins/jhttest");
		props.setProperty("scriptdir", "src/test/httest");
		props.setProperty("reportdir", "reports/httest");
		return props;
	}

	public static Collection<Object[]> data() throws Exception {
		Properties props = HttestIntTestClassRunner.getProperties();
		return collectHttestScript(props);
	}

	/**
	 * setup httest
	 * @note: you could activate verbose as well here, should be able to set with properties
	 */
	@Override
	@Before
	public void setUp() throws Exception {
		super.setUp(HttestIntTestClassRunner.getProperties());
		setVerbose(true);
	}
	
	/**
	 * Test runner
	 * @throws Exception
	 */
	@Test
	@HttSubDir("")
	public void testHttTests() throws Exception {
		getHttest().runScript("src/test/httest/sample/sample.htt");
	}
	
	/**
	 * Test runner
	 * @throws Exception
	 */
	@Test
	@HttSubDir("src/test/httest/sample/")
	public void testHttTests2() throws Exception {
		getHttest().runScript("src/test/httest/sample/sample2.htt");
	}

}
