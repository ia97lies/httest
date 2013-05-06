/*
 * Author            : AdNovum Informatik AG
 * Version Number    : $Revision: $
 * Date of last edit : $Date: $
 */

package ch.sf.htt;

import org.junit.Ignore;
import org.junit.runner.Description;
import org.junit.runner.notification.RunNotifier;
import org.junit.runners.BlockJUnit4ClassRunner;
import org.junit.runners.model.FrameworkMethod;
import org.junit.runners.model.InitializationError;

/**
 * @author AdNovum Informatik AG
 */
public class HttestRunner extends BlockJUnit4ClassRunner {
	public HttestRunner(Class<?> klass) throws InitializationError {
	    super(klass);
	    System.out.println(klass.getCanonicalName());
	}
	
	protected void runChild(FrameworkMethod method, RunNotifier notifier) {
		Description description = describeChild(method);
		if (method.getAnnotation(Ignore.class) != null) {
			notifier.fireTestIgnored(description);
		}
		else {
			runLeaf(methodBlock(method), description, notifier);
		}
	}
	    
    public @interface Httest {  
        String value();  
    }  
}
