/*
 * Author            : AdNovum Informatik AG
 * Version Number    : $Revision: $
 * Date of last edit : $Date: $
 */

package ch.sf.htt;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.reflect.Method;
import java.util.Properties;

import org.junit.Ignore;
import org.junit.internal.AssumptionViolatedException;
import org.junit.internal.runners.model.EachTestNotifier;
import org.junit.runner.Description;
import org.junit.runner.notification.RunNotifier;
import org.junit.runners.BlockJUnit4ClassRunner;
import org.junit.runners.model.FrameworkMethod;
import org.junit.runners.model.InitializationError;

/**
 * @author AdNovum Informatik AG
 */
public class HttestClassRunner extends BlockJUnit4ClassRunner {
	String subdir;
	Properties props;
	
	public HttestClassRunner(Class<?> klass) throws InitializationError {
	    super(klass);
    	System.out.println("INIT");
    	System.out.println(klass.getCanonicalName());
	    try {
	    	Method m = klass.getDeclaredMethod("getProperties", null);
	    	props = (Properties )m.invoke(null);
	    }
	    catch (Exception e) {
	    	System.out.println("ERROR "+e.getLocalizedMessage());
	    }
	}
	
	protected void runChild(FrameworkMethod method, RunNotifier notifier) {
		HttSubDir subdir;
		Description description = describeChild(method);
		if (method.getAnnotation(Ignore.class) != null) {
			notifier.fireTestIgnored(description);
			System.out.println("IGNORE");
		}
		else if ((subdir = method.getAnnotation(HttSubDir.class)) != null) {
			System.out.println("FOO");
			System.out.println("XXX" + subdir.value());
			System.out.println("PROPS: " + this.props.getProperty("basedir"));
			// collect tests methods to excute but perhaps not here?
			EachTestNotifier eachNotifier = new EachTestNotifier(notifier, description);
			eachNotifier.fireTestStarted();
			try {
				methodBlock(method).evaluate();
			} catch (AssumptionViolatedException e) {
				eachNotifier.addFailedAssumption(e);
			} catch (Throwable e) {
				eachNotifier.addFailure(e);
			} finally {
				eachNotifier.fireTestFinished();
			}
		}
		else {
			runLeaf(methodBlock(method), description, notifier);
		}
	}
	   
	@Retention(value=RetentionPolicy.RUNTIME)
    public @interface HttSubDir {
    	String value();
    }  
}
