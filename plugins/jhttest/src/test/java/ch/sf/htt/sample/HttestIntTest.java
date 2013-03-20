/*
 * Author            : AdNovum Informatik AG
 * Version Number    : $Revision: $
 * Date of last edit : $Date: $
 */

package ch.sf.htt.sample;

import java.io.File;
import java.io.FileInputStream;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Properties;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

import ch.sf.htt.HttestWrapper;

/**
 * A test class to run all httest scripts below $basedir/src/test/httest
 * @author AdNovum Informatik AG
 */
@RunWith(Parameterized.class)
public class HttestIntTest extends HttestWrapper {

	private String file;
	private Properties props;

	public HttestIntTest(String file) {
		this.file = file;
	}

	/**
	 * setup httest
	 * @note: you could activate verbose as well here, should be able to set with properties
	 */
	@Override
	@Before
	public void setUp() throws Exception {
		props = new Properties();
		props.load(new FileInputStream("/home/cli/.htt/htt.properties"));
		props.setProperty("basedir", "/home/cli/projects/htt/plugins/jhttest");
		super.setUp(props);
		setVerbose(true);
	}

	/**
	 * Collect all files below a folder like $basedir/src/test/httest
	 * @param file IN staring point to collect httest scripts
	 * @param all IN a collection of script names
	 */
	public static void addTree(File file, Collection<Object[]> all) {
		File[] children = file.listFiles();
		if (children != null) {
			for (File child : children) {
				if (child.isFile()) {
					String script = "src/test/httest/"+file.getName()+"/"+child.getName();
					Object[] data = new Object[] { script };
					all.add(data);
				}
				addTree(child, all);
			}
		}
	}

	/**
	 * Collect all files below $basedir/src/test/httest
	 * @return return collection
	 * @note: this is used vor parametrized junit tests
	 */
	@Parameters(name="{index}: {0}")
	public static Collection<Object[]> data() {
		//Object[][] data = new Object[][] { { "sample/adminLogin.htt" }, { "sample/upAndRunning.htt" } };
		Collection<Object[]> data = new ArrayList<Object[]>();
		addTree(new File("/home/cli/projects/htt/plugins/jhttest/src/test/httest"), data);
		return data;
	}

	/**
	 * Test runner
	 * @throws Exception
	 */
	@Test
	public void httTests() throws Exception {
		getHttest().runScript(file);
	}

}
