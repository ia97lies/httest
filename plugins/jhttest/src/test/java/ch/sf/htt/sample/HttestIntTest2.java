/*
 * Author            : AdNovum Informatik AG
 * Version Number    : $Revision: $
 * Date of last edit : $Date: $
 */

package ch.sf.htt.sample;

import java.io.FileInputStream;
import java.util.Properties;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import ch.sf.htt.HttestRunner;
import ch.sf.htt.HttestRunner.Httest;
import ch.sf.htt.HttestWrapper;

/**
 * @author AdNovum Informatik AG
 */
@RunWith(HttestRunner.class)
public class HttestIntTest2 extends HttestWrapper {
	public HttestIntTest2() {
		super("");
	}
	
	private static Properties getProperties() throws Exception {
		Properties props;
		props = new Properties();
		props.load(new FileInputStream("/home/cli/.htt/htt.properties"));
		props.setProperty("basedir", "/home/cli/projects/htt/plugins/jhttest");
		props.setProperty("scriptdir", "src/test/httest");
		return props;
	}
	
	/**
	 * setup httest
	 * @note: you could activate verbose as well here, should be able to set with properties
	 */
	@Override
	@Before
	public void setUp() throws Exception {
		super.setUp(HttestIntTest2.getProperties());
		setVerbose(true);
	}
	
	/**
	 * Test runner
	 * @throws Exception
	 */
	@Test
	@Httest("src/test/httest")
	public void testHttTests() throws Exception {
		getHttest().runScript("src/test/httest/sample/sample.htt");
	}
	
	/**
	 * Test runner
	 * @throws Exception
	 */
	@Test
	@Httest("src/test/httest")
	public void testHttTests2() throws Exception {
		getHttest().runScript("src/test/httest/sample/sample2.htt");
	}

}
